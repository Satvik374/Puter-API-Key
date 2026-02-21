import { getAuthToken } from "@heyputer/puter.js/src/init.cjs";

try {
  const token = await getAuthToken();
  console.log("");
  console.log("Copy this into your .env file:");
  console.log(`PUTER_AUTH_TOKEN=${token}`);
  console.log("");
} catch (error) {
  console.error("Failed to get Puter auth token:");
  console.error(error?.message || error);
  process.exit(1);
}
