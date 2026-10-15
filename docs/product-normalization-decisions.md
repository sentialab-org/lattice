# Product Normalization Execution Decisions

Date: 2026-10-15. These decisions preserve the approved product scope and record
where source verification stops. No minor review findings were deferred.
Items 1-22 record source-preparation decisions before rollout approval; subsequent
entries record their approved deployment and current acceptance boundaries.

1. Work directly on main in /Users/zvwgvx/Project/lattice — explicitly approved by owner and plan — no isolated branch; protected source snapshot retained.

2. Private provision and remote publication are deferred to prepared release review; local auth implementation and tests are already authorized — avoid accidental external changes — live acceptance remains separate.

3. New network defaults use approved 10.77.0.0/16; existing network.json stays authoritative — historical generic 10.240 fixture expectations were aligned — no migration of allocated IPs.

4. Gateway firewall has accept base policy with drops scoped to owned overlay interface — old global drop policy could interrupt unrelated traffic — unrelated host firewall may still require operator integration.

5. Shared atomic byte writer creates mode-0600 random temporary files before writing — prior gateway writer exposed private config briefly — Windows replacement semantics need platform acceptance.

6. Persist pending delegation before executing mutations; uncertain interrupted requests fail closed for inspection, finished responses are cached, queued job IDs derive from delegation IDs — prevents duplicate mutations after an ambiguous crash — interrupted responses may need operator inspection instead of transparent retry.

7. Promote immutable version directory, retain all old versions and stable.previous, then atomically replace stable pointer — avoids deleting an existing published tree — entry-script updates are separately copied and require release review.

8. Require per-target build-record hashes and one source revision; require macOS managed bash 4+ along with WireGuard tools and notices — stock macOS bash is too old for upstream wg-quick — missing redistributable dependencies block real assembly, not fixture validation.

9. The downloaded Chromium 1208 extraction stalled under Node 26; use the existing complete Chromium 1243 executable through LATTICE_BROWSER_EXECUTABLE — real browser tests passed with Playwright 1.58.2 — CI can install the locked package's browser normally.

10. System IPC defaults to /run/lattice/node.sock on Linux and /var/run/lattice/node.sock on macOS, mode 0660; macOS admin group and explicit Linux installing-user group receive access — root state remains private and clients reuse one daemon — old binaries using /tmp require the system installer migration.

11. Preserve the running Edge combined role until workload handover and HTTPS are reviewed — fresh read-only inspection found existing combined authority and an HTTP origin — switching directly could strand active leases or prevent Secure-cookie login.

12. Prepare owner Argon2id account verifier privately in the protected local backup directory, without deploying it — source and local preparation are authorized but live migration still requires concrete review — account login is not yet production-verified.

13. Build portable managed network dependencies from pinned upstream source and retain corresponding source/notices — stock macOS Bash and private Homebrew linkage cannot be redistributed as-is — native execution/driver acceptance still needs each actual OS.

14. Plain Linux cross-check lacks aarch64-linux-gnu-gcc; use the release's cargo-zigbuild/glibc 2.28 toolchain for Linux verification — it performs the actual target compilation and linking — target runtime acceptance remains separate.

15. Actual root/reboot/WireGuard/TCP and native Windows UAC/SCM acceptance remain unjudged until actual hosts are exercised — source checks cannot establish these gates — shipping without that acceptance could retain platform defects.

16. Production account/TLS/publication/workload handover remain deferred to concrete deployment review — no running Edge services or protected credentials are changed by review — public normalization remains unavailable until rollout.

17. Public ordinary admission remains the approved behavior — no extra enrollment secret or approval is introduced — open membership remains an intentional product property.

18. Interrupted delegated mutations retain fail-closed inspection behavior — durable pending records avoid duplicate execution — an ambiguous request can require manual inspection.

19. All five target builds completed at 1b4a773 after review began, but must be rebuilt after corrections — successful linking does not prove installation — pre-fix artifacts are not release candidates.

20. Existing leases keep their old control pin during master handover and retain policy/expiry handling — automatically replacing the pin would strand the running lease — handover can wait until the current lease terminates or expires.

21. Persist coordinator directory with a 120-second freshness bound and recheck at lease/control/update acceptance — signed master keys alone do not express current authority — coordinator outages can pause new control operations while existing leases continue.

22. Allow HTTP content only for the exact authenticated master origin and owned content-object paths; general content validation remains HTTPS/loopback — workloads need WireGuard overlay downloads without weakening arbitrary URL validation — routing/native driver acceptance remains separate.

23. The owner approved the concrete rollout, pilot and main push — publish immutable candidates, migrate the existing Edge service and HTTPS ingress, and exercise actual installers — this approval satisfies the earlier deployment review boundary; no repeated push/deploy approval is required.

24. Keep 0.2.0 and 0.2.1 immutable after native pilot failures; publish corrected installer bundles as 0.2.2 — systemd environment-file parsing and stale Unix socket readiness failed on real hosts — neither earlier candidate is eligible for stable.

25. Migrate legacy HTTP bootstrap URLs only after matching the existing coordinator ID and fingerprint to the verified HTTPS origin — strict pinning intentionally rejects an unrelated URL — retain node identity, private/WireGuard keys, allocations and owner policy.

26. Exercise revocation using a temporary participating Ubuntu master, then restore Core as active and return Ubuntu to an ordinary node — actual authority removal must be tested without leaving the intended network without a master — no active lease was cancelled.

27. Reboot and disconnect only the dedicated idle Ubuntu pilot VM — Core hosts other VMs and Mac is the owner's workstation — service restart evidence does not claim those host reboots.

28. The owner prioritized Linux after confirming that additional native target hosts were unavailable — complete available Linux verification and record other targets explicitly — builds, a black Windows console and ARM64 gateway execution do not establish their participating-node installer acceptance.

29. Leave global stable unset while advertised native target gates remain incomplete — explicit-version Linux pilot installation is available at 0.2.2 — do not silently narrow the original cross-platform product scope or treat Linux prioritization as acceptance of untested platforms.
