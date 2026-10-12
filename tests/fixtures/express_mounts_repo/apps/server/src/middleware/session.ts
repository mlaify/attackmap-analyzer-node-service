export function authenticate(req: any, res: any, next: () => void) {
  if (!req.session?.user) return res.sendStatus(401);
  next();
}
