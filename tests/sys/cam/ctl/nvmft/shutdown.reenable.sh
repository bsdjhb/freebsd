atf_test_case %%MODE%%_%%RMODE%%
%%MODE%%_%%RMODE%%_head()
{
	atf_set "descr" "%%MODE%% reenable then %%RMODE%% with no delay"
	require
}

%%MODE%%_%%RMODE%%_body()
{
	reenable_test %%MODE%% %%RMODE%%
}

atf_test_case %%MODE%%_%%RMODE%%_short_delay
%%MODE%%_%%RMODE%%_short_delay_head()
{
	atf_set "descr" "%%MODE%% reenable then %%RMODE%% with 1 second delay"
	require
}

%%MODE%%_%%RMODE%%_short_delay_body()
{
	reenable_test %%MODE%% %%RMODE%% 1
}

atf_test_case %%MODE%%_%%RMODE%%_long_delay
%%MODE%%_%%RMODE%%_long_delay_head()
{
	atf_set "descr" "%%MODE%% reenable then %%RMODE%% with 130 second delay"
	require
}

%%MODE%%_%%RMODE%%_long_delay_body()
{
	reenable_xfail %%MODE%% %%RMODE%% 130
}
