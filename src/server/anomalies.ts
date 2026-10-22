export interface HourlyAccessCount {
  hour: number;
  count: number;
}

export function countOffHoursAccess(
  hourlyCounts: readonly HourlyAccessCount[]
): number {
  return hourlyCounts.reduce(
    (total, item) =>
      item.hour < 6 || item.hour >= 22 ? total + item.count : total,
    0
  );
}
