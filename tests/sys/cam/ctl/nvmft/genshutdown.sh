# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Chelsio Communications, Inc.

# Generate shutdown.sh

# Shared routines used by individual tests
header()
{
	cat <<EOF
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Chelsio Communications, Inc.

require()
{
	atf_set "require.config" "nvmft.nqn nvmft.address nvmft.port"
}

fetch_vars()
{
	CMD=\$(atf_get_srcdir)/nvmf_shutdown
	NQN=\$(atf_config_get nvmft.nqn)
	ADDRESS=\$(atf_config_get nvmft.address):\$(atf_config_get nvmft.port)
}

# \$1 - mode
# \$2 - delay (optional)
shutdown_test()
{
	local delay

	if [ "\$#" -eq 2 ]; then
		delay="-d \$2"
	fi

	fetch_vars

	atf_check \$CMD \$delay \$1 "\$ADDRESS" "\$NQN"
}

# \$1 - mode
# \$2 - reenable mode
# \$3 - reenable delay (optional)
reenable_test()
{
	local delay

	if [ "\$#" -eq 3 ]; then
		delay="-D \$3"
	fi

	fetch_vars

	atf_check \$CMD \$delay -R \$2 \$1 "\$ADDRESS" "\$NQN"
}

# \$1 - mode
# \$2 - reenable mode
# \$3 - reenable delay
reenable_xfail()
{
	fetch_vars

	atf_check -s exit:1 -e match:"Connection reset" \\
	    \$CMD -D \$3 -R \$2 \$1 "\$ADDRESS" "\$NQN"
}

EOF
}

# Test a shutdown mode without re-enabling
simple_test()
{
	cat <<EOF
atf_test_case ${1}
${1}_head()
{
	atf_set "descr" "${1} with no delay"
	require
}

${1}_body()
{
	shutdown_test ${1}
}

atf_test_case ${1}_short_delay
${1}_short_delay_head()
{
	atf_set "descr" "${1} with 1 second delay"
	require
}

${1}_short_delay_body()
{
	shutdown_test ${1} 1
}

atf_test_case ${1}_long_delay
${1}_long_delay_head()
{
	atf_set "descr" "${1} with 130 second delay"
	require
}

${1}_long_delay_body()
{
	shutdown_test ${1} 130
}

EOF
	TESTS="${TESTS} ${1} ${1}_short_delay ${1}_long_delay"
}

# Test a shutdown mode and then reenable
reenable_test()
{
	cat <<EOF
atf_test_case ${1}_${2}
${1}_${2}_head()
{
	atf_set "descr" "${1} reenable then ${2} with no delay"
	require
}

${1}_${2}_body()
{
	reenable_test ${1} ${2}
}

atf_test_case ${1}_${2}_short_delay
${1}_${2}_short_delay_head()
{
	atf_set "descr" "${1} reenable then ${2} with 1 second delay"
	require
}

${1}_${2}_short_delay_body()
{
	reenable_test ${1} ${2} 1
}

atf_test_case ${1}_${2}_long_delay
${1}_${2}_long_delay_head()
{
	atf_set "descr" "${1} reenable then ${2} with 130 second delay"
	require
}

${1}_${2}_long_delay_body()
{
	reenable_xfail ${1} ${2} 130
}

EOF
	TESTS="${TESTS} ${1}_${2} ${1}_${2}_short_delay ${1}_${2}_long_delay"
}

# Generate the test harness glue
trailer()
{
	cat <<EOF
atf_init_test_cases()
{
EOF
	for t in $TESTS; do
		echo "	atf_add_test_case ${t}"
	done

	echo "}"
}

MODES="normal abrupt close reset"
TESTS=""

header
for mode in $MODES; do
	simple_test $mode

	# "close" doesn't support reenable
	if [ "$mode" = "close" ]; then
		continue
	fi

	for rmode in $MODES; do
		reenable_test $mode $rmode
	done
done
trailer
