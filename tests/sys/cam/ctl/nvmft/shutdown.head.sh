# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Chelsio Communications, Inc.

require()
{
	atf_set "require.config" "nqn address port"
}

fetch_vars()
{
	CMD=$(atf_get_srcdir)/nvmf_shutdown
	NQN=$(atf_config_get nqn)
	ADDRESS=$(atf_config_get address):$(atf_config_get port)
}

# $1 - mode
# $2 - delay (optional)
shutdown_test()
{
	local delay

	if [ "$#" -eq 2 ]; then
		delay="-d $2"
	fi

	fetch_vars

	atf_check $CMD $delay $1 "$ADDRESS" "$NQN"
}

# $1 - mode
# $2 - reenable mode
# $3 - reenable delay (optional)
reenable_test()
{
	local delay

	if [ "$#" -eq 3 ]; then
		delay="-D $3"
	fi

	fetch_vars

	atf_check $CMD $delay -R $2 $1 "$ADDRESS" "$NQN"
}

# $1 - mode
# $2 - reenable mode
# $3 - reenable delay
reenable_xfail()
{
	fetch_vars

	atf_check -s exit:1 -e match:"Connection reset" \
	    $CMD -D $3 -R $2 $1 "$ADDRESS" "$NQN"
}
