export const config = {
  // These are inlined into the client bundle at build time. Any secret
  // set through them is effectively public.
  bitdriftKey: process.env.EXPO_PUBLIC_BITDRIFT_API_KEY,
  posthogKey: process.env.EXPO_PUBLIC_POSTHOG_KEY,

  // These stay server-side.
  jwtSecret: process.env.JWT_SIGNING_KEY,
};
