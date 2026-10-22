import { describe, expect, it } from "vitest";
import { countOffHoursAccess } from "../src/server/anomalies.js";

describe("off-hours anomaly aggregation", () => {
  it("counts UTC hours before 06:00 and from 22:00 onward only", () => {
    expect(
      countOffHoursAccess([
        { hour: 0, count: 2 },
        { hour: 5, count: 3 },
        { hour: 6, count: 100 },
        { hour: 21, count: 100 },
        { hour: 22, count: 4 },
        { hour: 23, count: 5 }
      ])
    ).toBe(14);
  });
});
