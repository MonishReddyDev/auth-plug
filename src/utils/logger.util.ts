// src/utils/logger.util.ts

export function logError(error: any, req?: any) {
  // Basic log info
  console.error("====== ERROR LOG START ======");
  console.error("Time:", new Date().toISOString());
  if (req) {
    console.error("Request URL:", req.originalUrl || req.url);
    console.error("Method:", req.method);
    console.error(
      "User:",
      req.user ? JSON.stringify(req.user) : "Unauthenticated"
    );
    console.error("IP:", req.ip);
    if (req.body) console.error("Body:", JSON.stringify(req.body));
    if (req.query) console.error("Query:", JSON.stringify(req.query));
  }
  // Error details
  console.error("Error message:", error.message);
  if (error.stack) console.error("Stack trace:", error.stack);
  console.error("====== ERROR LOG END ======\n");
}
