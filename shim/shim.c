#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define DEBUG_ENABLED 0

#if DEBUG_ENABLED
#define DEBUG(fmt, ...) dprintf(shim_debug_fd, fmt __VA_OPT__(,) __VA_ARGS__)
static int shim_debug_fd;
#else
#define DEBUG(fmt, ...)
#endif

// implemented in libvos.so
extern int VOS_CfgParamGet(char* file, char* param, void* dest, size_t len);

// implemented in here
void* payload_postboot(void*);

#define EMR_TASK 0x5000
#define EMR_MSG_CFG_UNI_PPTP 0x90006

struct EmrCfgUniPptp {
    uint32_t slot;
    uint32_t port;
    char _8[8];
    uint32_t enable;
    uint32_t loopback;
    uint32_t mode;
    char _1C[4];
    uint32_t usRate;
    uint32_t dsRate;
    uint32_t pausetime;
    char _2C[8];
    uint32_t EthFilter;
    uint32_t Dot1xEnable;
    uint32_t ActionRegister;
    uint32_t AuthenticatorPAEState;
    char _44[4];
    char _48[8];
};

static int (*orig_VOS_SendSyncMsg)(uint32_t dest_id, uint32_t msg_id, int flags, void* msg_buf, size_t msg_len, void* rsp_buf, size_t rsp_len, int timeout);
int VOS_SendSyncMsg(uint32_t dest_id, uint32_t msg_id, int flags, void* msg_buf, size_t msg_len, void* rsp_buf, size_t rsp_len, int timeout)
{
	if (dest_id == EMR_TASK && msg_id == EMR_MSG_CFG_UNI_PPTP)
	{
		// Config UNI Eth message is going out, we need to make sure that l2_drv.ko doesn't know that the OLT doesn't
		// want it to pass traffic
		struct EmrCfgUniPptp* report = (struct EmrCfgUniPptp *) msg_buf;

		DEBUG("VOS_SendSyncMsg EMR_MSG_CFG_UNI_PPTP: 802.1x enabled %d action %d auth state %d\n",
				report->Dot1xEnable, report->ActionRegister, report->AuthenticatorPAEState);

		report->Dot1xEnable = 0;
		report->ActionRegister = 3;
		report->AuthenticatorPAEState = 0;
	}

	return orig_VOS_SendSyncMsg(dest_id, msg_id, flags, msg_buf, msg_len, rsp_buf, rsp_len, timeout);
}

static int (*orig_VOS_CfgParamGetByName)(char* name, void* dest, size_t len);
int VOS_CfgParamGetByName(char* param, void* dest, size_t len)
{
	// this is mandatory, as this is the first thing the real one does
	// and if we _don't_ do this we're going to wind up sending stack
	// contents in MIB entries and making the OLT mad at us
	memset(dest, 0, len);

	if (!VOS_CfgParamGet("/mnt/rwdir/payload.cfg", param, dest, len))
		return 0;

	return orig_VOS_CfgParamGetByName(param, dest, len);
}

static int (*orig_VOS_ExecStr)(int unk, char* cmd);
int VOS_ExecStr(int unk, char* cmd)
{
	char serial[0x20];

	if (!strcmp(cmd, "mv -f /tmp/scfg.tmp /tmp/scfg.txt")
	 && !VOS_CfgParamGetByName("EepEqSerialNumber", &serial, sizeof(serial)))
	{
		// this is MiscMgr writing out the scfg for libscfg.ko, which is the
		// last remaining source of the eeprom serial/vendor getting observed
		//
		// fortunately the two fields we two about are the first two that get
		// written, and the sizes are fixed, so we can get away with using
		// fixed offsets into the file. if we wanted to be more robust to
		// firmware updates (unlikely to change this anyways) we could read
		// the whole thing in and find the right fields... or we could just
		// do this.
		int fd = open("/tmp/scfg.tmp", O_RDWR);

		lseek(fd, 0x20, SEEK_SET);
		write(fd, &serial, 4);

		lseek(fd, 0x40, SEEK_SET);
		write(fd, &serial[4], 8);

		close(fd);
	}

	return orig_VOS_ExecStr(unk, cmd);
}


static int (*orig_VOS_SpawnAppl)(int pri, int stack, int id, char* name);
int VOS_SpawnAppl(int pri, int stack, int id, char* name)
{
	if (id == EMR_TASK)
	{
		// EthMgr is the final process SspMgr starts, so now we'll spin up our
		// thread that waits a bit and then starts dropbear -- it doesn't seem
		// to like starting during early boot much at all and log output is not
		// illuminating.
		pthread_t thread;
		pthread_create(&thread, NULL, payload_postboot, NULL);
	}

	return orig_VOS_SpawnAppl(pri, stack, id, name);
}

void _init()
{
#if DEBUG_ENABLED
	shim_debug_fd = open("/dev/kmsg", O_WRONLY);
#endif

	DEBUG("FS.com XGS-PON shim initializing\n");

	orig_VOS_SendSyncMsg = dlsym(RTLD_NEXT, "VOS_SendSyncMsg");
	orig_VOS_CfgParamGetByName = dlsym(RTLD_NEXT, "VOS_CfgParamGetByName");
	orig_VOS_ExecStr = dlsym(RTLD_NEXT, "VOS_ExecStr");
	orig_VOS_SpawnAppl = dlsym(RTLD_NEXT, "VOS_SpawnAppl");
}

void* payload_postboot(void* arg)
{
	int attempts_remaining = 1000;
	struct timespec wait = { 100, 0 };
	struct timespec rem;

	// we eat EINTR a lot while sleeping, typically have ~300 restarts
	while (nanosleep(&wait, &rem) != 0 && --attempts_remaining)
		wait = rem;

	if (attempts_remaining)
	{
		close(open("/tmp/payload_postboot_dropbear", O_CREAT | O_WRONLY, S_IRWXU));

		// it's hopefully been long enough that this is happy now
		orig_VOS_ExecStr(0, "dropbear");

		// we made it to the end and didn't eat too many signals, this means it's
		// actually safe to consider re-arming automarically if enabled
		if (!access("/mnt/rwdir/payload_auto_rearm", F_OK))
		{
			unlink("/mnt/rwdir/disarmed");
			sync();
		}
	}

	// leaving this around to help possible trouble-shooting in the future:
	// if dropbear didn't start but this file exists we know this is related
	// to large amounts of EINTR during startup
	int fd = open("/tmp/payload_postboot_end", O_CREAT | O_WRONLY, S_IRWXU);
	write(fd, &attempts_remaining, sizeof(attempts_remaining));
	close(fd);

	return NULL;
}
