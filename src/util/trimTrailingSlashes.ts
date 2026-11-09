/**
 * Removes trailing "/" characters. Written as a loop rather than /\/+$/ so that long
 * inputs cannot trigger catastrophic backtracking (ReDoS).
 */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(0, end);
}
