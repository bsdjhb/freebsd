atf_test_case %%MODE%%
%%MODE%%_head()
{
	atf_set "descr" "%%MODE%% with no delay"
	require
}

%%MODE%%_body()
{
	shutdown_test %%MODE%%
}

atf_test_case %%MODE%%_short_delay
%%MODE%%_short_delay_head()
{
	atf_set "descr" "%%MODE%% with 1 second delay"
	require
}

%%MODE%%_short_delay_body()
{
	shutdown_test %%MODE%% 1
}

atf_test_case %%MODE%%_long_delay
%%MODE%%_long_delay_head()
{
	atf_set "descr" "%%MODE%% with 130 second delay"
	require
}

%%MODE%%_long_delay_body()
{
	shutdown_test %%MODE%% 130
}
