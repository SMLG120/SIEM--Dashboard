import { alert, expect, mockApi, signInAs, test } from "./fixtures";

test.describe("Command Overview", () => {
  test("shows persisted open-alert counts and top rules @mobile", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Command Overview" })).toBeVisible();
    const metrics = page.getByLabel("Security metrics");
    await expect(metrics.getByText("Critical")).toBeVisible();
    await expect(metrics.getByText("3", { exact: true })).toBeVisible();
    await expect(metrics.getByText("42", { exact: true })).toBeVisible();
  });

  test("every primary page is reachable from the navigation", async ({ page }) => {
    await signInAs(page, ["ADMIN"]);
    await mockApi(page);
    await page.goto("/");
    const nav = page.getByRole("complementary", { name: "Primary navigation" });
    for (const [link, heading] of [
      ["Live Events", "Live Events"],
      ["Alerts", "Alerts"],
      ["Incidents", "Incident Investigation"],
      ["Detection Rules", "Detection Rules"],
      ["Threat Intel", "Threat Intel"],
      ["Platform Health", "Platform Health"],
      ["Overview", "Command Overview"]
    ]) {
      await nav.getByRole("link", { name: link, exact: true }).click();
      await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    }
  });
});

test.describe("Alert triage", () => {
  test("drawer explains why the alert fired and links ATT&CK", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/alerts");
    await page.getByRole("row", { name: /Brute force from single source/ }).click();

    const drawer = page.getByRole("dialog", { name: "Alert details" });
    await expect(drawer.getByText("Why this alert fired")).toBeVisible();
    await expect(drawer.getByText("sourceIp=198.51.100.7")).toBeVisible();
    await expect(drawer.getByText("count = 10 >= 10 per sourceIp within 300s")).toBeVisible();
    await expect(drawer.getByRole("link", { name: /T1110.001/ })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/001/"
    );
    await expect(drawer.getByText("CREATED")).toBeVisible();
  });

  test("analyst can resolve an alert", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/alerts");
    await page.getByRole("row", { name: /Brute force/ }).click();
    const resolve = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/api/alerts/alert-0001/resolve"));
    await page.getByRole("dialog").getByRole("button", { name: "Resolve" }).click();
    await resolve;
  });

  test("server rejections are shown, not swallowed", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page, {
      "POST /api/alerts/alert-0001/resolve": (route) =>
        route.fulfill({
          status: 409,
          contentType: "application/json",
          body: JSON.stringify({ detail: "Cannot move alert from RESOLVED to RESOLVED" })
        })
    });
    await page.goto("/alerts");
    await page.getByRole("row", { name: /Brute force/ }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Resolve" }).click();
    await expect(page.getByText("Cannot move alert from RESOLVED to RESOLVED (HTTP 409)")).toBeVisible();
  });

  test("filters are sent to the search API", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/alerts");
    await expect(page.getByText("1 matching")).toBeVisible();
    const filtered = page.waitForRequest((r) => r.url().includes("/api/alerts/search") && r.url().includes("severity=CRITICAL"));
    await page.getByRole("group", { name: "Severity" }).getByRole("button", { name: "CRITICAL" }).click();
    await filtered;
  });

  test("viewer sees evidence but no workflow actions", async ({ page }) => {
    await signInAs(page, ["VIEWER"]);
    await mockApi(page);
    await page.goto("/alerts");
    await page.getByRole("row", { name: /Brute force/ }).click();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByText("Why this alert fired")).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Resolve" })).toHaveCount(0);
    await expect(drawer.getByLabel("New note")).toHaveCount(0);
  });
});

test.describe("Detection rules", () => {
  test("shows logic, ATT&CK and false positives; sandbox test reports alerts", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/rules");
    const detail = page.getByLabel("Rule SIEM-1008");
    await expect(detail.getByText("count >= 10 per sourceIp within 300s")).toBeVisible();
    await expect(detail.getByText("A user repeatedly typing an expired password")).toBeVisible();
    await expect(detail.getByRole("button", { name: /Disable rule/ })).toHaveCount(0); // analysts can't change rules

    const request = page.waitForRequest((r) => r.url().endsWith("/api/rules/test"));
    await detail.getByRole("button", { name: "Run test" }).click();
    const body = (await request).postDataJSON() as { ruleId: string; events: unknown[] };
    expect(body.ruleId).toBe("SIEM-1008");
    expect(body.events).toHaveLength(1);
    await expect(detail.getByText("would fire")).toContainText("1 alert would fire");
  });

  test("invalid test input is rejected client-side", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    await mockApi(page);
    await page.goto("/rules");
    await page.getByLabel("Events JSON").fill("{not json");
    await page.getByRole("button", { name: "Run test" }).click();
    await expect(page.locator(".form-error")).toBeVisible();
  });

  test("manager can disable a rule", async ({ page }) => {
    await signInAs(page, ["SOC_MANAGER"]);
    await mockApi(page, {
      "POST /api/rules/SIEM-1008/disable": (route) =>
        route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "SIEM-1008" }) })
    });
    await page.goto("/rules");
    const disable = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/api/rules/SIEM-1008/disable"));
    await page.getByRole("button", { name: "Disable rule" }).click();
    await disable;
  });

  test("tactic filter narrows the catalogue", async ({ page }) => {
    await signInAs(page, ["VIEWER"]);
    await mockApi(page);
    await page.goto("/rules");
    const list = page.getByRole("list", { name: "Detection rules" });
    await expect(list.getByRole("listitem")).toHaveCount(2);
    await page.getByLabel("Tactic").selectOption("Execution");
    await expect(list.getByRole("listitem")).toHaveCount(1);
    await expect(list).toContainText("SIEM-1010");
  });
});

test.describe("Threat intel", () => {
  test("labels simulated data and lists sightings @mobile", async ({ page }) => {
    await signInAs(page, ["VIEWER"]);
    await mockApi(page);
    await page.goto("/threat-intel");
    await expect(page.getByRole("note")).toContainText("No external threat feeds are connected");
    await expect(page.getByText("simulated", { exact: true })).toBeVisible();
    await expect(page.getByText("destinationIp")).toBeVisible();
    await expect(page.getByRole("form", { name: "Add indicator" })).toHaveCount(0);
  });

  test("manager adds an indicator", async ({ page }) => {
    await signInAs(page, ["SOC_MANAGER"]);
    await mockApi(page, {
      "POST /api/threat-intel/indicators": (route) =>
        route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ id: "ioc-2" }) })
    });
    await page.goto("/threat-intel");
    await page.getByLabel("Indicator type").selectOption("DOMAIN");
    await page.getByLabel("Indicator value").fill("bad.example.org");
    await page.getByLabel("Description").fill("phishing landing page");
    const request = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/api/threat-intel/indicators"));
    await page.getByRole("button", { name: "Add indicator" }).click();
    expect((await request).postDataJSON()).toEqual({
      type: "DOMAIN",
      value: "bad.example.org",
      severity: "HIGH",
      description: "phishing landing page"
    });
  });
});

test.describe("Platform health", () => {
  test("managers see the audit trail and live service status", async ({ page }) => {
    await signInAs(page, ["SOC_MANAGER"]);
    await mockApi(page);
    await page.goto("/platform");
    await expect(page.getByLabel("Service health").getByText("ready").first()).toBeVisible();
    await expect(page.getByText("3.4 ms")).toBeVisible();
    await expect(page.getByLabel("Audit trail")).toContainText("RULE_DISABLE");
  });

  test("analysts do not see or request the audit trail", async ({ page }) => {
    await signInAs(page, ["SECURITY_ANALYST"]);
    let auditRequested = false;
    await mockApi(page, {
      "GET /api/audit/events": (route) => {
        auditRequested = true;
        return route.fulfill({ status: 403 });
      }
    });
    await page.goto("/platform");
    await expect(page.getByLabel("Service health")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Audit trail" })).toHaveCount(0);
    expect(auditRequested).toBe(false);
  });
});

test("unknown routes fall back to the overview", async ({ page }) => {
  await signInAs(page, ["VIEWER"]);
  await mockApi(page);
  await page.goto("/does-not-exist");
  await expect(page.getByRole("heading", { level: 1, name: "Command Overview" })).toBeVisible();
  expect(alert.id).toBeTruthy();
});
