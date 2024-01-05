#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

static int (*orig_VOS_CfgBackParamGetByName)(char* name, void* dest, size_t len);
int VOS_CfgBackParamGetByName(char* param, void* dest, size_t len)
{
	memset(dest, 0, len);

	// To enable setting both A/B sw versions, we intercept when it tries
	// to read the version from the backup config and divert it to the
	// payload config if it's provided. Necessary for ALCL ONTs on ALCL OLTs.
	if (!strcmp(param, "SWVER")
	 && !VOS_CfgParamGet("/mnt/rwdir/payload.cfg", "SWVER_BACK", dest, len))
		return 0;

	return orig_VOS_CfgBackParamGetByName(param, dest, len);
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

// VLAN filtering/rule 'improvement' support
//
// Some ISPs (Orange in France) ship more extended vlan rules down than this
// stick supports to some customers. This stick supports at most 17, but up
// to 22 have been observed. Unfortunately, the rules we need were at the end
// and so are silently dropped.
//
// Interestingly, a lot of these rules are all for individual priority levels
// of various VLANs. While only some of these VLANs are needed for internet
// service, we can attempt to keep other services working by weakening the
// priority match (e.g., instead of 'match pri 0, send pri 0' we can do 'match
// any pri, sent orig pri') and winding up with only ONE rule per vlan.
//
// This requires the user's own gateway to be careful to not send any traffic
// with a wrong priority up.
//
// NOTE: this INTENTIONALLY does not support effort changing the VID involved
// in match rules, or insertion of any rules. This can at most DROP rules or
// rewrite priority fields for inner tags.
//
// Rules for untagged frames and 2-tagged frames are always passed as I've
// not seen that be an issue anywhere yet.

struct vlan_mod_rule {
	int vid; // must match inner vid filt of entry
	int inner_pri_filt; // -1 to match any, otherwise must match entry
	int inner_pri_new; // -2 to drop rule, -1 to preserve, any other value to set
	int treat_pri_new; // -1 to preserve, any other value to set
	int valid;
};

struct RxFrmOpTblEntry {
	uint16_t EntityID;
	uint8_t OuterPriFilter;
	char _3[1];
	uint16_t OuterVidFilter;
	uint8_t OuterTPIDFilter;
	uint8_t InnerPriFilter;
	uint16_t InnerVidFilter;
	uint8_t InnerTPIDFilter;
	uint8_t EtherTypeFilter;
	uint8_t AniBriPortNum;
	uint8_t RmTagTreat;
	uint8_t OuterPriTreat;
	char _f[1];
	uint16_t OuterVidTreat;
	uint8_t OuterTPIDTreat;
	uint8_t InnerPriTreat;
	uint16_t InnerVidTreat;
	uint8_t InnerTPIDTreat;
	char _17[1];
};

#define VLAN_MAX_MOD_RULES  17

static int vlan_parse_int(char** pos, int* dst)
{
	if (**pos == 0)
		return 0;

	char* oldpos = *pos;
	*dst = strtol(*pos, pos, 0);
	if (*pos == oldpos)
		return 0;

	// skip past the next ',', if any
	if (**pos == ',')
		*pos += 1;

	return 1;
}

enum vlan_filter_action {
	DROP,
	PASS,
};

static enum vlan_filter_action vlan_should_filter(struct RxFrmOpTblEntry* entry)
{
	static struct vlan_mod_rule vlan_mod_rules[VLAN_MAX_MOD_RULES];
	static int vlan_rules_initialized = 0;

	// 2-tagged rule
	if (entry->OuterPriFilter != 0xf)
		return PASS;

	// default 1-tagged or untagged rule
	if (entry->InnerPriFilter >= 0xe)
		return PASS;

	if (!vlan_rules_initialized)
	{
		char vlan_rule_string[0x100];

		// VOS_CfgParamGet does not null terminate if it runs out of space
		memset(vlan_rule_string, 0, sizeof(vlan_rule_string));

		if (!VOS_CfgParamGet("/mnt/rwdir/payload.cfg", "VLAN_MOD_RULES", vlan_rule_string, sizeof(vlan_rule_string)-1))
		{
			char* cur_pos = vlan_rule_string;

			for (int i = 0; i < VLAN_MAX_MOD_RULES; i++)
			{
				if (!vlan_parse_int(&cur_pos, &vlan_mod_rules[i].vid)
				 || !vlan_parse_int(&cur_pos, &vlan_mod_rules[i].inner_pri_filt)
				 || !vlan_parse_int(&cur_pos, &vlan_mod_rules[i].inner_pri_new)
				 || !vlan_parse_int(&cur_pos, &vlan_mod_rules[i].treat_pri_new))
					break;

				vlan_mod_rules[i].valid = 1;
			}
		}

		vlan_rules_initialized = 1;
	}

	// at this point, we know it's a 1 tag rule, and by convention only
	// the 'inner' part of the rules should be used.
	for (int i = 0; i < VLAN_MAX_MOD_RULES && vlan_mod_rules[i].valid; i++)
	{
		struct vlan_mod_rule* rule = &vlan_mod_rules[i];

		// vlan match *must* be explicit
		if (rule->vid != entry->InnerVidFilter)
			continue;

		// inner priority filter match is optional, to allow expression of rules
		// that drop all rules for a given vlan without knowing rule priority
		if (rule->inner_pri_filt >= 0 && rule->inner_pri_filt != entry->InnerPriFilter)
			continue;

		if (rule->inner_pri_new == -2)
			return DROP;

		if (rule->inner_pri_new >= 0)
			entry->InnerPriFilter = rule->inner_pri_new;

		if (rule->treat_pri_new >= 0)
			entry->InnerPriTreat = rule->treat_pri_new;

		// first rule with a match takes an action and halts
		// further rules
		break;
	}

	return PASS;
}

static int (*orig_MIB_GetNextSub)(int id, void* out, size_t len);
int MIB_GetNextSub(int id, void* out, size_t len)
{
	int ret;

	while (!(ret = orig_MIB_GetNextSub(id, out, len))
	    && (id == 0x5f) && (vlan_should_filter(out) == DROP));

	return ret;
}

static int (*orig_MIB_GetFirstSub)(int id, void* out, size_t len);
int MIB_GetFirstSub(int id, void* out, size_t len)
{
	int ret = orig_MIB_GetFirstSub(id, out, len);

	// if the first rule is one that needs to be skipped,
	// implement this in terms of the advance function
	if ((id == 0x5f) && (vlan_should_filter(out) == DROP))
		return MIB_GetNextSub(id, out, len);

	return ret;
}

void _init()
{
#if DEBUG_ENABLED
	shim_debug_fd = open("/dev/kmsg", O_WRONLY);
#endif

	DEBUG("FS.com XGS-PON shim initializing\n");

	orig_VOS_SendSyncMsg = dlsym(RTLD_NEXT, "VOS_SendSyncMsg");
	orig_VOS_CfgParamGetByName = dlsym(RTLD_NEXT, "VOS_CfgParamGetByName");
	orig_VOS_CfgBackParamGetByName = dlsym(RTLD_NEXT, "VOS_CfgBackParamGetByName");
	orig_VOS_ExecStr = dlsym(RTLD_NEXT, "VOS_ExecStr");
	orig_VOS_SpawnAppl = dlsym(RTLD_NEXT, "VOS_SpawnAppl");

	// while most binaries this shim is loaded by don't link against libmib,
	// these will just be harmless NULL pointers that won't ever be reached
	// unless we got loaded by MecMgr.
	orig_MIB_GetFirstSub = dlsym(RTLD_NEXT, "MIB_GetFirstSub");
	orig_MIB_GetNextSub = dlsym(RTLD_NEXT, "MIB_GetNextSub");
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
