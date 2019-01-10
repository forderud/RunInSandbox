# ComImpersonation
Work-in-progress code for launching a COM server through a different user.

WARNING: Does not work yet. Have submitted [DCOM registration timeout when attempting to start a COM server through a different user](https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ) to StackOverflow to request advise.


### Overview of subproblems

| Subproblem          | Status                                                                      |
|---------------------|-----------------------------------------------------------------------------|
|Run as user          | :white_check_mark: (confirmed)                                              |
|Environment variables| :x: Inherited from client process user (inconsistent with impersonated user)|
|Registry setup       | :x: Unknown                                                                 |
