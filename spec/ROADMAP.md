# Roadmap

This document names the phases of the work. The "Done by" column of the
[implementation register](STATUS.md) refers to these phase IDs. At the exit of a
phase, each unit with that "Done by" value must have the state `done`.

| Phase | Name         | Exit condition                                                                                              |
| ----- | ------------ | ----------------------------------------------------------------------------------------------------------- |
| P1    | Crypto core  | The crypto shim is complete, and all known-answer tests pass.                                               |
| P2    | Oracle logic | The record store and the get/set state machine are complete, and the unit tests pass.                       |
| P3    | Service      | The CGI, the sandbox, and the deployment configuration are complete, and the upstream interop suite passes. |
| P4    | Distribution | The ports, the man pages, and the pkg-readme are complete, and a live reference client passes validation.   |

The phases run in order: P1, P2, P3, P4.
