const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;

export function validatePassword(password: string): string | null {
  if (!PASSWORD_PATTERN.test(password)) {
    return "Password must be at least 12 characters with upper, lower, digit, and symbol.";
  }
  return null;
}
