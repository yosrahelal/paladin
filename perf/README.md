# Paladin Performance CLI

Paladin Performance CLI is a HTTP load testing tool that generates a constant request rate against a Paladin node and measures performance. This is used to confirm confidence that a Paladin node can perform under normal conditions for an extended period of time.

## Items Subject to Testing

- Public transaction submission

## Build

The `pldperf` CLI needs building before you can use it.

Run `gradle build` in the root directory to build and install the `pldperf` command.

## Run

### Public contract

TODO:
- explain what test does
- explain prereqs of installing contract and creating a listener
- how to run the test

## Command line options

```
Usage:
  pldperf run [flags]

Flags:
  -c, --config string          Path to performance config that describes the nodes and test instances
  -d, --daemon                 Run in long-lived, daemon mode. Any provided test length is ignored.
      --delinquent string      Action to take when delinquent messages are detected. Valid options: [exit log] (default "exit")
  -h, --help                   help for run
  -i, --instance-idx int       Index of the instance within performance config to run (default -1)
  -n, --instance-name string   Instance within performance config to run
```

## Metrics

The `pldperf` tool registers the following metrics for prometheus to consume:

- pldperf_runner_actions_submitted_total
- pldperf_runner_received_events_total
- pldperf_runner_incomplete_events_total
- pldperf_runner_deliquent_msgs_total
- pldperf_runner_perf_test_duration_seconds

## Useful features

The `pldperf` tool is designed to let you run various styles of test. There are various options for creating your own customized tests. A full list of configuration options can be seen at [`conf.go`](internal/conf/conf.go) but some useful options are outlined below:

- Setting a maximum number of test actions
  - See `maxActions` attribute (defaults to `0` i.e. unlimited).
  - Once `maxActions` test actions (e.g. token mints) have taken place the test will shut down.
- Ending the test when an error occurs
  - See `delinquentAction` attribute (defaults to `exit`).
  - A value of `exit` causes the test to end if an error occurs. Set to `log` to simply log the error and continue the test.
- Set the maximum duration of the test
  - See `length` attribute.
  - Setting a test instance's `length` attribute to a time duration (e.g. `3h`) will cause the test to run for that long or until an error occurs (see `delinquentAction`).
  - Note this setting is ignored if the test is run in daemon mode (running the `pldperf` command with `-d` or `--daemon`, or setting the global `daemon` value to `true` in the `instances.yaml` file). In daemon mode the test will run until `maxActions` has been reached or an error has occurred and `delinquentActions` is set to true.
- Ramping up the rate of test actions (e.g. token mints)
  - See the `startRate`, `endRate` and `rateRampUpTime` attribute of a test instance.
  - All values default to `0` which has the effect of not limiting the rate of the test.
  - The test will allow at most `startRate` actions to happen per second. Over the period of `rateRampUpTime` seconds the allowed rate will increase linearly until `endRate` actions per seconds are reached. At this point the test will continue at `endRate` actions per second until the test finishes.
  - If `startRate` is the only value that is set, the test will run at that rate for the entire test.
- Waiting for events to be confirmed before doing the next submission
  - See `noWaitSubmission` (defaults to `false`).
  - When set to `true` each worker routine will perform its action (e.g. minting a token) and wait for confirmation of that event before doing its next action.
  - `maxSubmissionsPerSecond` can be used to control the maximum number of submissions per second to avoid overloading the system under test.
- Having a worker loop submit more than 1 action per loop by setting `actionsPerLoop` for the test. This can be helpful when you want to scale the number of actions done in parallel without having to scale the number of workers. The default value is `1` for this attribute. If setting to a value > `1` it is recommended to have `noWaitSubmission` to set `false`.
