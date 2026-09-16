# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Chelsio Communications, Inc.

. $(atf_get_srcdir)/ctld.subr

atf_test_case shutdown cleanup
shutdown_head()
{
	atf_set "descr" "Various association shutdown scenarios"
	requires_ctld

	# Lots of near two-minute delays
	# XXX: A timeout of 0 trips an assertion failure in kyua
	# rather than disabling the timeout as documented
	atf_set "timeout" "3600"
}

shutdown_body()
{
	start_ctld

	CMD=$(atf_get_srcdir)/nvmf_shutdown
	ARGS="127.0.0.1:4420 nqn.1994-09.org.freebsd:test"

	for m in normal abrupt close reset; do
		# Tests without reenable
		echo "$m"
		atf_check $CMD $m $ARGS

		echo "-d 1 $m"
		atf_check $CMD -d 1 $m $ARGS

		echo "-d 130 $m"
		atf_check $CMD -d 130 $m $ARGS

		# close doesn't support reenable
		if [ "$m" == "close" ]; then
			continue
		fi

		# Tests which reenable the controller
		for rm in normal abrupt close reset; do
			echo "-R $rm $m"
			atf_check $CMD -R $rm $m $ARGS

			# Should be able to re-enable within 2 minutes
			echo "-R $rm -D 100 $m"
			atf_check $CMD -R $rm -D 100 $m $ARGS

			# Should fail as it re-enables after 2 minutes
			echo "-R $rm -D 130 $m (should fail)"
			atf_check -s exit:1 -e match:"Connection reset" \
			    $CMD -R $rm -D 130 $m $ARGS
		done
	done
}

shutdown_cleanup()
{
	cleanup_ctld
}

atf_init_test_cases()
{
	atf_add_test_case shutdown
}
