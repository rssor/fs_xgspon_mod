#!/bin/sh

BASEDIR=/mnt/rwdir

if [ ! -f $BASEDIR/disarmed ]; then
        touch $BASEDIR/disarmed

        # if we're not supposed to be persistent, nuke symlink
        [ ! -f $BASEDIR/payload_auto_rearm ] && rm $BASEDIR/setup.sh

        sync

        $BASEDIR/dangerous_payload.sh
        touch /tmp/payload_stage0
fi

# always return error so that we never halt /sbin/setup.sh
exit 1
