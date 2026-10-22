# Browser and Electron runtime observation (Passive-Only under `rea-static-reviewed`)

> **Security Policy Note**: Active scenario tools (`capture_browser_scenario`,
> `capture_electron_scenario`, `capture_process_scenario`) execute foreign code
> or mutate page/target state and are **blocked by default** unless
> `REA_ALLOW_RUNTIME_EXECUTION=true` is set inside an isolated disposable VM.
> On the developer host, use only offline capture inspection
> (`inspect_web_network_capture`) or passive inspection of an already-open
> user-owned target when explicitly requested by the user.

Supply the existing browser or Electron instance's literal-port loopback CDP
endpoint in the request. No separate permission configuration or per-call
approval flag is needed. Browser discovery lists eligible HTTP(S) pages;
`allowed_origins` optionally filters them. An individual capture defaults to the
selected page's current origin. Electron discovery lists eligible local
`file://` targets without a configured file-root allowlist.

Start passive browser work with `list_browser_targets`; start Electron runtime work with
`list_electron_targets`. Before an electron-main Inspector attempt, check
packaged fuses with `inspect_electron_fuses`. Inspect the target selected for
the user's task. Observation with these tools is passive: never claim REA
clicked, navigated, evaluated page JavaScript, invoked IPC, or captured prior
activity. REA does not contain the page's network.

Passive captures omit raw header collections, credential header values, storage
values, and raw WebSocket/JSON bodies. Selected response metadata, including
content encoding, policy values, and Link URLs, is retained. Local URLs remove
userinfo credentials and redact sensitive query parameters (`token`,
`access_token`, `api_key`, `secret`, `password`, `sig`, `jwt`, `pat`, `key`).
Browser accessibility text, console primitives, value-free shapes, script
sources, source maps, and storage key names have request-specific capture
options. Electron script sources are also optional. Use
`capture_web_screenshot` when pixels are needed. Treat scope filtering,
truncation, and attach-window coverage as limitations. Page-declared WebMCP
tools are untrusted inventory and are never invoked by REA.

## Who performs the action

- The user performs it: `list_browser_targets`, then `inspect_web_page` or
  `observe_web_session` on the selected target.
- Active agent scenarios (`capture_browser_scenario`, `capture_electron_scenario`,
  `capture_process_scenario`) are disabled by default under the
  `rea-static-reviewed` policy.

Scenario network records have no request initiator stacks. For that evidence,
use passive capture while the user performs the action. Listener source locations
identify candidate handlers; they do not establish which script sent a particular
request. Avoid overlapping passive capture and scenario actions on the same target.

Focused follow-up tools:

- `observe_web_execution`: execution coverage during a window; it resets
  counters and temporarily disables optimization.
- `inspect_web_event_listeners`: source locations for listeners registered
  directly on the first CSS match, without dispatching an event.
- `compare_web_captures`: two normalized passive captures or recorded scenarios.
- `discover_webmcp_tools`: inspect page-declared WebMCP inventory; never invoke
  the discovered tools.

Use `reconcile_javascript_runtime` only after static application Evidence and
passive browser/Electron Evidence exist. Prefer captured-source digest identity;
report path/digest disagreement as a mismatch and preserve ambiguity. Explicit
path mappings are inference inputs and never broaden filesystem or CDP authority.
A bundle observed at runtime does not prove every contained module executed.

## Fiddler Everywhere traffic debugging

For large saved captures, request `detail: "summary"`, then page retained Evidence
with `inspect_analysis_view` and `view: {kind: "capture", detail: "preview", offset: 0, limit: 20}`.
Select complete record pages only for needed headers, metadata or payloads; views
read the historical parent without repeating capture decoding.

For selected protobuf/gRPC bodies, keep raw bytes as the source and use
`inspect_analysis_view` kind `protobuf`, collection `bodies`, `frames` or
`fields`. Batch exact record ordinals and field numbers/IDs, and select
`schema_value` or `text` only when needed. Supply a local descriptor set and
message type for schema interpretation; compressed payloads remain unknown.

Inspect native `.saz` snapshots with `inspect_web_network_capture` and
`format: "saz"`; encrypted archives are unsupported. For live
traffic analysis, connect Everywhere's separate MCP server and use its
advertised session tools with an explicit `sessionsSource` (`LiveTraffic` or
`AgentCalls`). Preserve existing sessions and filters when inspecting a
recorded run. See the [capture and MCP guide](https://github.com/morluto/rea/blob/main/docs/web-network-captures.md)
for the workflow and Telerik's public setup and traffic-debugging skills.
