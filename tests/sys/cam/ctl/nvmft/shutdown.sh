# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Chelsio Communications, Inc.

require()
{
	atf_set "require.config" "nvmft.nqn nvmft.address nvmft.port"
}

fetch_vars()
{
	CMD=$(atf_get_srcdir)/nvmf_shutdown
	NQN=$(atf_config_get nvmft.nqn)
	ADDRESS=$(atf_config_get nvmft.address):$(atf_config_get nvmft.port)
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

atf_test_case normal
normal_head()
{
	atf_set "descr" "normal with no delay"
	require
}

normal_body()
{
	shutdown_test normal
}

atf_test_case normal_short_delay
normal_short_delay_head()
{
	atf_set "descr" "normal with 1 second delay"
	require
}

normal_short_delay_body()
{
	shutdown_test normal 1
}

atf_test_case normal_long_delay
normal_long_delay_head()
{
	atf_set "descr" "normal with 130 second delay"
	require
}

normal_long_delay_body()
{
	shutdown_test normal 130
}

atf_test_case normal_normal
normal_normal_head()
{
	atf_set "descr" "normal reenable then normal with no delay"
	require
}

normal_normal_body()
{
	reenable_test normal normal
}

atf_test_case normal_normal_short_delay
normal_normal_short_delay_head()
{
	atf_set "descr" "normal reenable then normal with 1 second delay"
	require
}

normal_normal_short_delay_body()
{
	reenable_test normal normal 1
}

atf_test_case normal_normal_long_delay
normal_normal_long_delay_head()
{
	atf_set "descr" "normal reenable then normal with 130 second delay"
	require
}

normal_normal_long_delay_body()
{
	reenable_xfail normal normal 130
}

atf_test_case normal_abrupt
normal_abrupt_head()
{
	atf_set "descr" "normal reenable then abrupt with no delay"
	require
}

normal_abrupt_body()
{
	reenable_test normal abrupt
}

atf_test_case normal_abrupt_short_delay
normal_abrupt_short_delay_head()
{
	atf_set "descr" "normal reenable then abrupt with 1 second delay"
	require
}

normal_abrupt_short_delay_body()
{
	reenable_test normal abrupt 1
}

atf_test_case normal_abrupt_long_delay
normal_abrupt_long_delay_head()
{
	atf_set "descr" "normal reenable then abrupt with 130 second delay"
	require
}

normal_abrupt_long_delay_body()
{
	reenable_xfail normal abrupt 130
}

atf_test_case normal_close
normal_close_head()
{
	atf_set "descr" "normal reenable then close with no delay"
	require
}

normal_close_body()
{
	reenable_test normal close
}

atf_test_case normal_close_short_delay
normal_close_short_delay_head()
{
	atf_set "descr" "normal reenable then close with 1 second delay"
	require
}

normal_close_short_delay_body()
{
	reenable_test normal close 1
}

atf_test_case normal_close_long_delay
normal_close_long_delay_head()
{
	atf_set "descr" "normal reenable then close with 130 second delay"
	require
}

normal_close_long_delay_body()
{
	reenable_xfail normal close 130
}

atf_test_case normal_reset
normal_reset_head()
{
	atf_set "descr" "normal reenable then reset with no delay"
	require
}

normal_reset_body()
{
	reenable_test normal reset
}

atf_test_case normal_reset_short_delay
normal_reset_short_delay_head()
{
	atf_set "descr" "normal reenable then reset with 1 second delay"
	require
}

normal_reset_short_delay_body()
{
	reenable_test normal reset 1
}

atf_test_case normal_reset_long_delay
normal_reset_long_delay_head()
{
	atf_set "descr" "normal reenable then reset with 130 second delay"
	require
}

normal_reset_long_delay_body()
{
	reenable_xfail normal reset 130
}

atf_test_case abrupt
abrupt_head()
{
	atf_set "descr" "abrupt with no delay"
	require
}

abrupt_body()
{
	shutdown_test abrupt
}

atf_test_case abrupt_short_delay
abrupt_short_delay_head()
{
	atf_set "descr" "abrupt with 1 second delay"
	require
}

abrupt_short_delay_body()
{
	shutdown_test abrupt 1
}

atf_test_case abrupt_long_delay
abrupt_long_delay_head()
{
	atf_set "descr" "abrupt with 130 second delay"
	require
}

abrupt_long_delay_body()
{
	shutdown_test abrupt 130
}

atf_test_case abrupt_normal
abrupt_normal_head()
{
	atf_set "descr" "abrupt reenable then normal with no delay"
	require
}

abrupt_normal_body()
{
	reenable_test abrupt normal
}

atf_test_case abrupt_normal_short_delay
abrupt_normal_short_delay_head()
{
	atf_set "descr" "abrupt reenable then normal with 1 second delay"
	require
}

abrupt_normal_short_delay_body()
{
	reenable_test abrupt normal 1
}

atf_test_case abrupt_normal_long_delay
abrupt_normal_long_delay_head()
{
	atf_set "descr" "abrupt reenable then normal with 130 second delay"
	require
}

abrupt_normal_long_delay_body()
{
	reenable_xfail abrupt normal 130
}

atf_test_case abrupt_abrupt
abrupt_abrupt_head()
{
	atf_set "descr" "abrupt reenable then abrupt with no delay"
	require
}

abrupt_abrupt_body()
{
	reenable_test abrupt abrupt
}

atf_test_case abrupt_abrupt_short_delay
abrupt_abrupt_short_delay_head()
{
	atf_set "descr" "abrupt reenable then abrupt with 1 second delay"
	require
}

abrupt_abrupt_short_delay_body()
{
	reenable_test abrupt abrupt 1
}

atf_test_case abrupt_abrupt_long_delay
abrupt_abrupt_long_delay_head()
{
	atf_set "descr" "abrupt reenable then abrupt with 130 second delay"
	require
}

abrupt_abrupt_long_delay_body()
{
	reenable_xfail abrupt abrupt 130
}

atf_test_case abrupt_close
abrupt_close_head()
{
	atf_set "descr" "abrupt reenable then close with no delay"
	require
}

abrupt_close_body()
{
	reenable_test abrupt close
}

atf_test_case abrupt_close_short_delay
abrupt_close_short_delay_head()
{
	atf_set "descr" "abrupt reenable then close with 1 second delay"
	require
}

abrupt_close_short_delay_body()
{
	reenable_test abrupt close 1
}

atf_test_case abrupt_close_long_delay
abrupt_close_long_delay_head()
{
	atf_set "descr" "abrupt reenable then close with 130 second delay"
	require
}

abrupt_close_long_delay_body()
{
	reenable_xfail abrupt close 130
}

atf_test_case abrupt_reset
abrupt_reset_head()
{
	atf_set "descr" "abrupt reenable then reset with no delay"
	require
}

abrupt_reset_body()
{
	reenable_test abrupt reset
}

atf_test_case abrupt_reset_short_delay
abrupt_reset_short_delay_head()
{
	atf_set "descr" "abrupt reenable then reset with 1 second delay"
	require
}

abrupt_reset_short_delay_body()
{
	reenable_test abrupt reset 1
}

atf_test_case abrupt_reset_long_delay
abrupt_reset_long_delay_head()
{
	atf_set "descr" "abrupt reenable then reset with 130 second delay"
	require
}

abrupt_reset_long_delay_body()
{
	reenable_xfail abrupt reset 130
}

atf_test_case close
close_head()
{
	atf_set "descr" "close with no delay"
	require
}

close_body()
{
	shutdown_test close
}

atf_test_case close_short_delay
close_short_delay_head()
{
	atf_set "descr" "close with 1 second delay"
	require
}

close_short_delay_body()
{
	shutdown_test close 1
}

atf_test_case close_long_delay
close_long_delay_head()
{
	atf_set "descr" "close with 130 second delay"
	require
}

close_long_delay_body()
{
	shutdown_test close 130
}

atf_test_case reset
reset_head()
{
	atf_set "descr" "reset with no delay"
	require
}

reset_body()
{
	shutdown_test reset
}

atf_test_case reset_short_delay
reset_short_delay_head()
{
	atf_set "descr" "reset with 1 second delay"
	require
}

reset_short_delay_body()
{
	shutdown_test reset 1
}

atf_test_case reset_long_delay
reset_long_delay_head()
{
	atf_set "descr" "reset with 130 second delay"
	require
}

reset_long_delay_body()
{
	shutdown_test reset 130
}

atf_test_case reset_normal
reset_normal_head()
{
	atf_set "descr" "reset reenable then normal with no delay"
	require
}

reset_normal_body()
{
	reenable_test reset normal
}

atf_test_case reset_normal_short_delay
reset_normal_short_delay_head()
{
	atf_set "descr" "reset reenable then normal with 1 second delay"
	require
}

reset_normal_short_delay_body()
{
	reenable_test reset normal 1
}

atf_test_case reset_normal_long_delay
reset_normal_long_delay_head()
{
	atf_set "descr" "reset reenable then normal with 130 second delay"
	require
}

reset_normal_long_delay_body()
{
	reenable_xfail reset normal 130
}

atf_test_case reset_abrupt
reset_abrupt_head()
{
	atf_set "descr" "reset reenable then abrupt with no delay"
	require
}

reset_abrupt_body()
{
	reenable_test reset abrupt
}

atf_test_case reset_abrupt_short_delay
reset_abrupt_short_delay_head()
{
	atf_set "descr" "reset reenable then abrupt with 1 second delay"
	require
}

reset_abrupt_short_delay_body()
{
	reenable_test reset abrupt 1
}

atf_test_case reset_abrupt_long_delay
reset_abrupt_long_delay_head()
{
	atf_set "descr" "reset reenable then abrupt with 130 second delay"
	require
}

reset_abrupt_long_delay_body()
{
	reenable_xfail reset abrupt 130
}

atf_test_case reset_close
reset_close_head()
{
	atf_set "descr" "reset reenable then close with no delay"
	require
}

reset_close_body()
{
	reenable_test reset close
}

atf_test_case reset_close_short_delay
reset_close_short_delay_head()
{
	atf_set "descr" "reset reenable then close with 1 second delay"
	require
}

reset_close_short_delay_body()
{
	reenable_test reset close 1
}

atf_test_case reset_close_long_delay
reset_close_long_delay_head()
{
	atf_set "descr" "reset reenable then close with 130 second delay"
	require
}

reset_close_long_delay_body()
{
	reenable_xfail reset close 130
}

atf_test_case reset_reset
reset_reset_head()
{
	atf_set "descr" "reset reenable then reset with no delay"
	require
}

reset_reset_body()
{
	reenable_test reset reset
}

atf_test_case reset_reset_short_delay
reset_reset_short_delay_head()
{
	atf_set "descr" "reset reenable then reset with 1 second delay"
	require
}

reset_reset_short_delay_body()
{
	reenable_test reset reset 1
}

atf_test_case reset_reset_long_delay
reset_reset_long_delay_head()
{
	atf_set "descr" "reset reenable then reset with 130 second delay"
	require
}

reset_reset_long_delay_body()
{
	reenable_xfail reset reset 130
}

atf_init_test_cases()
{
	atf_add_test_case normal
	atf_add_test_case normal_short_delay
	atf_add_test_case normal_long_delay
	atf_add_test_case normal_normal
	atf_add_test_case normal_normal_short_delay
	atf_add_test_case normal_normal_long_delay
	atf_add_test_case normal_abrupt
	atf_add_test_case normal_abrupt_short_delay
	atf_add_test_case normal_abrupt_long_delay
	atf_add_test_case normal_close
	atf_add_test_case normal_close_short_delay
	atf_add_test_case normal_close_long_delay
	atf_add_test_case normal_reset
	atf_add_test_case normal_reset_short_delay
	atf_add_test_case normal_reset_long_delay
	atf_add_test_case abrupt
	atf_add_test_case abrupt_short_delay
	atf_add_test_case abrupt_long_delay
	atf_add_test_case abrupt_normal
	atf_add_test_case abrupt_normal_short_delay
	atf_add_test_case abrupt_normal_long_delay
	atf_add_test_case abrupt_abrupt
	atf_add_test_case abrupt_abrupt_short_delay
	atf_add_test_case abrupt_abrupt_long_delay
	atf_add_test_case abrupt_close
	atf_add_test_case abrupt_close_short_delay
	atf_add_test_case abrupt_close_long_delay
	atf_add_test_case abrupt_reset
	atf_add_test_case abrupt_reset_short_delay
	atf_add_test_case abrupt_reset_long_delay
	atf_add_test_case close
	atf_add_test_case close_short_delay
	atf_add_test_case close_long_delay
	atf_add_test_case reset
	atf_add_test_case reset_short_delay
	atf_add_test_case reset_long_delay
	atf_add_test_case reset_normal
	atf_add_test_case reset_normal_short_delay
	atf_add_test_case reset_normal_long_delay
	atf_add_test_case reset_abrupt
	atf_add_test_case reset_abrupt_short_delay
	atf_add_test_case reset_abrupt_long_delay
	atf_add_test_case reset_close
	atf_add_test_case reset_close_short_delay
	atf_add_test_case reset_close_long_delay
	atf_add_test_case reset_reset
	atf_add_test_case reset_reset_short_delay
	atf_add_test_case reset_reset_long_delay
}
