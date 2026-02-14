import { MongoClient, ObjectId } from "npm:mongodb@6.12.0";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function err(message: string, status = 400) {
  return json({ message }, status);
}

// ---------- JWT helpers (HMAC-SHA256) ----------
async function getKey() {
  const secret = Deno.env.get("JWT_SECRET") || "fallback-secret";
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

function base64url(buf: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signJWT(payload: Record<string, unknown>) {
  const key = await getKey();
  const header = base64url(
    new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .buffer
  );
  const body = base64url(
    new TextEncoder().encode(
      JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 86400 * 7 })
    ).buffer
  );
  const sig = base64url(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${header}.${body}`))
  );
  return `${header}.${body}.${sig}`;
}

async function verifyJWT(token: string): Promise<Record<string, unknown> | null> {
  try {
    const key = await getKey();
    const [header, body, sig] = token.split(".");
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(
      atob(body.replace(/-/g, "+").replace(/_/g, "/"))
    );
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- Password helpers ----------
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  const saltHex = [...salt].map((b) => b.toString(16).padStart(2, "0")).join("");
  const hashHex = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, hashHex] = stored.split(":");
  const salt = Uint8Array.from(saltHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  const computed = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return computed === hashHex;
}

// ---------- Referral code generator ----------
function genReferralCode() {
  return "VG" + Math.random().toString(36).substring(2, 8).toUpperCase();
}

// ---------- MongoDB ----------
let client: MongoClient | null = null;

async function getDb() {
  if (!client) {
    const uri = Deno.env.get("MONGODB_URI");
    if (!uri) throw new Error("MONGODB_URI not configured");
    client = new MongoClient(uri);
    await client.connect();
  }
  return client.db("vaultgrow");
}

// ---------- Auth middleware ----------
async function authenticate(req: Request) {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return await verifyJWT(auth.slice(7));
}

// ---------- Routes ----------

async function handleRegister(body: any) {
  const { fullName, email, phone, password, referralCode } = body;
  if (!fullName || !email || !phone || !password)
    return err("All fields are required");

  const db = await getDb();
  const users = db.collection("users");

  const existing = await users.findOne({ email });
  if (existing) return err("Email already registered");

  const hashedPw = await hashPassword(password);
  const newRefCode = genReferralCode();

  const user: any = {
    fullName,
    email,
    phone,
    password: hashedPw,
    referralCode: newRefCode,
    walletBalance: 700, // welcome bonus
    totalInvested: 0,
    referralEarnings: 0,
    withdrawableBalance: 0,
    activeInvestments: 0,
    isBlocked: false,
    isAdmin: false,
    createdAt: new Date(),
  };

  // Handle referral - just store the referrer, bonus is paid when user invests
  if (referralCode) {
    const referrer = await users.findOne({ referralCode });
    if (referrer) {
      user.referredBy = referrer._id;
      user.referralBonusPaid = false; // Track if referrer got bonus
    }
  }

  await users.insertOne(user);
  return json({ message: "Registration successful" }, 201);
}

async function handleLogin(body: any) {
  const { email, password } = body;
  if (!email || !password) return err("Email and password required");

  const db = await getDb();
  const user = await db.collection("users").findOne({ email });
  if (!user) return err("Invalid credentials");
  if (user.isBlocked) return err("Account is blocked");

  const valid = await verifyPassword(password, user.password);
  if (!valid) return err("Invalid credentials");

  const isAdmin = user.isAdmin === true;
  const token = await signJWT({ userId: user._id.toString(), isAdmin });
  return json({
    token,
    isAdmin,
    user: {
      id: user._id.toString(),
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      referralCode: user.referralCode,
    },
  });
}

async function handleAdminLogin(body: any) {
  const { email, password } = body;
  const db = await getDb();
  const admin = await db.collection("users").findOne({ email, isAdmin: true });
  if (!admin) return err("Invalid admin credentials");

  const valid = await verifyPassword(password, admin.password);
  if (!valid) return err("Invalid admin credentials");

  const token = await signJWT({ userId: admin._id.toString(), isAdmin: true });
  return json({ token });
}

async function handleDashboard(userId: string) {
  const db = await getDb();
  const user = await db.collection("users").findOne({ _id: new ObjectId(userId) });
  if (!user) return err("User not found", 404);

  // Calculate total ROI earned from completed/active investments
  const investments = await db.collection("investments").find({
    userId,
    status: { $in: ["confirmed", "completed"] },
  }).toArray();

  const totalRoiEarned = investments.reduce((sum: number, inv: any) => {
    const daysCompleted = inv.roiDaysCompleted || 0;
    return sum + (inv.amount * 0.15 * daysCompleted);
  }, 0);

  return json({
    walletBalance: user.walletBalance || 0,
    totalInvested: user.totalInvested || 0,
    activeInvestments: user.activeInvestments || 0,
    referralEarnings: user.referralEarnings || 0,
    referralCode: user.referralCode,
    totalRoiEarned,
  });
}

async function handleTransactions(userId: string) {
  const db = await getDb();
  const investments = await db.collection("investments").find({ userId }).sort({ createdAt: -1 }).toArray();
  const payments = await db.collection("payments").find({ userId }).sort({ createdAt: -1 }).toArray();
  const withdrawals = await db.collection("withdrawals").find({ userId }).sort({ createdAt: -1 }).toArray();
  return json({ investments, payments, withdrawals });
}

async function handleCreateInvestment(userId: string, body: any) {
  const { planId, amount } = body;
  if (!planId || !amount) return err("Plan and amount required");

  const plans: Record<string, string> = {
    starter: "Starter Growth",
    silver: "Silver Growth",
    gold: "Gold Growth",
    platinum: "Platinum Growth",
  };

  const db = await getDb();
  await db.collection("investments").insertOne({
    userId,
    planId,
    planName: plans[planId] || planId,
    amount,
    dailyROI: 15,
    status: "pending",
    createdAt: new Date(),
  });

  await db.collection("users").updateOne(
    { _id: new ObjectId(userId) },
    { $inc: { totalInvested: amount, activeInvestments: 1 } }
  );

  // Pay referral bonus on first investment
  const investingUser = await db.collection("users").findOne({ _id: new ObjectId(userId) });
  if (investingUser?.referredBy && investingUser?.referralBonusPaid === false) {
    await db.collection("users").updateOne(
      { _id: investingUser.referredBy },
      { $inc: { referralEarnings: 500, walletBalance: 500 } }
    );
    await db.collection("users").updateOne(
      { _id: new ObjectId(userId) },
      { $set: { referralBonusPaid: true } }
    );
  }

  return json({ message: "Investment created, pending confirmation. Admin will confirm your payment before returns begin." }, 201);
}

async function handleSubmitPayment(userId: string, body: any) {
  const { amount, reference } = body;
  if (!amount || !reference) return err("Amount and reference required");

  const db = await getDb();
  await db.collection("payments").insertOne({
    userId,
    amount,
    reference,
    status: "pending",
    createdAt: new Date(),
  });

  return json({ message: "Payment submitted, pending confirmation" }, 201);
}

async function handleReferral(userId: string) {
  const db = await getDb();
  const user = await db.collection("users").findOne({ _id: new ObjectId(userId) });
  if (!user) return err("User not found", 404);

  const totalReferrals = await db.collection("users").countDocuments({ referredBy: new ObjectId(userId) });
  return json({
    totalReferrals,
    referralEarnings: user.referralEarnings || 0,
    referralCode: user.referralCode,
  });
}

async function handleWithdraw(userId: string, body: any) {
  const { amount, bankName, accountNumber, accountName } = body;
  if (!amount || !bankName || !accountNumber || !accountName)
    return err("All fields are required");
  if (amount < 3700) return err("Minimum withdrawal is ₦3,700");

  const db = await getDb();
  const user = await db.collection("users").findOne({ _id: new ObjectId(userId) });
  if (!user) return err("User not found", 404);
  if ((user.walletBalance || 0) < amount)
    return err("Insufficient balance");

  await db.collection("withdrawals").insertOne({
    userId,
    userName: user.fullName,
    amount,
    bankName,
    accountNumber,
    accountName,
    status: "pending",
    createdAt: new Date(),
  });

  await db.collection("users").updateOne(
    { _id: new ObjectId(userId) },
    { $inc: { walletBalance: -amount } }
  );

  return json({ message: "Withdrawal request submitted" }, 201);
}

// ---------- Admin routes ----------

async function handleAdminOverview() {
  const db = await getDb();
  const users = db.collection("users");
  const investments = db.collection("investments");

  const totalUsers = await users.countDocuments({ isAdmin: { $ne: true } });
  const totalInvestments = await investments.countDocuments();
  const pendingInvestments = await investments.countDocuments({ status: "pending" });
  const confirmedInvestments = await investments.countDocuments({ status: "confirmed" });

  const allInvestments = await investments.find({ status: "confirmed" }).toArray();
  const totalPlatformIncome = allInvestments.reduce((sum: number, i: any) => sum + (i.amount || 0), 0);

  return json({
    totalUsers,
    totalInvestments,
    totalPlatformIncome,
    pendingInvestments,
    confirmedInvestments,
  });
}

async function handleAdminUsers() {
  const db = await getDb();
  const users = await db.collection("users")
    .find({ isAdmin: { $ne: true } })
    .project({ password: 0 })
    .sort({ createdAt: -1 })
    .toArray();

  return json(
    users.map((u: any) => ({
      id: u._id.toString(),
      fullName: u.fullName,
      email: u.email,
      phone: u.phone,
      walletBalance: u.walletBalance || 0,
      totalInvested: u.totalInvested || 0,
      isBlocked: u.isBlocked || false,
      createdAt: u.createdAt,
    }))
  );
}

async function handleToggleBlock(userId: string) {
  const db = await getDb();
  const user = await db.collection("users").findOne({ _id: new ObjectId(userId) });
  if (!user) return err("User not found", 404);

  await db.collection("users").updateOne(
    { _id: new ObjectId(userId) },
    { $set: { isBlocked: !user.isBlocked } }
  );

  return json({ message: user.isBlocked ? "User unblocked" : "User blocked" });
}

async function handleAdminInvestments() {
  const db = await getDb();
  const investments = await db.collection("investments").find().sort({ createdAt: -1 }).toArray();

  const userIds = [...new Set(investments.map((i: any) => i.userId))];
  const users = await db.collection("users")
    .find({ _id: { $in: userIds.map((id: string) => new ObjectId(id)) } })
    .project({ fullName: 1 })
    .toArray();
  const userMap = Object.fromEntries(users.map((u: any) => [u._id.toString(), u.fullName]));

  return json(
    investments.map((i: any) => ({
      id: i._id.toString(),
      userId: i.userId,
      userName: userMap[i.userId] || "Unknown",
      planName: i.planName,
      amount: i.amount,
      status: i.status,
      createdAt: i.createdAt,
    }))
  );
}

async function handleConfirmInvestment(body: any) {
  const { investmentId } = body;
  if (!investmentId) return err("Investment ID required");

  const db = await getDb();
  const result = await db.collection("investments").updateOne(
    { _id: new ObjectId(investmentId) },
    { $set: { status: "confirmed", confirmedAt: new Date(), roiDaysCompleted: 0, paymentConfirmed: true } }
  );

  if (result.matchedCount === 0) return err("Investment not found", 404);
  return json({ message: "Investment confirmed. Daily ROI will now begin for this user." });
}

async function handleAdminWithdrawals() {
  const db = await getDb();
  const withdrawals = await db.collection("withdrawals").find().sort({ createdAt: -1 }).toArray();

  return json(
    withdrawals.map((w: any) => ({
      id: w._id.toString(),
      userId: w.userId,
      userName: w.userName || "Unknown",
      amount: w.amount,
      bankName: w.bankName,
      accountNumber: w.accountNumber,
      accountName: w.accountName,
      status: w.status,
      createdAt: w.createdAt,
    }))
  );
}

async function handleApproveWithdrawal(body: any) {
  const { withdrawalId } = body;
  if (!withdrawalId) return err("Withdrawal ID required");

  const db = await getDb();
  const result = await db.collection("withdrawals").updateOne(
    { _id: new ObjectId(withdrawalId) },
    { $set: { status: "paid", paidAt: new Date() } }
  );

  if (result.matchedCount === 0) return err("Withdrawal not found", 404);
  return json({ message: "Withdrawal approved" });
}

async function handleAdminPayments() {
  const db = await getDb();
  const payments = await db.collection("payments").find().sort({ createdAt: -1 }).toArray();

  const userIds = [...new Set(payments.map((p: any) => p.userId))];
  const users = await db.collection("users")
    .find({ _id: { $in: userIds.map((id: string) => new ObjectId(id)) } })
    .project({ fullName: 1 })
    .toArray();
  const userMap = Object.fromEntries(users.map((u: any) => [u._id.toString(), u.fullName]));

  return json(
    payments.map((p: any) => ({
      id: p._id.toString(),
      userId: p.userId,
      userName: userMap[p.userId] || "Unknown",
      amount: p.amount,
      reference: p.reference,
      status: p.status,
      createdAt: p.createdAt,
    }))
  );
}

async function handleConfirmPayment(body: any) {
  const { paymentId } = body;
  if (!paymentId) return err("Payment ID required");

  const db = await getDb();
  const payment = await db.collection("payments").findOne({ _id: new ObjectId(paymentId) });
  if (!payment) return err("Payment not found", 404);

  await db.collection("payments").updateOne(
    { _id: new ObjectId(paymentId) },
    { $set: { status: "confirmed", confirmedAt: new Date() } }
  );

  // Credit user wallet
  await db.collection("users").updateOne(
    { _id: new ObjectId(payment.userId) },
    { $inc: { walletBalance: payment.amount } }
  );

  return json({ message: "Payment confirmed and wallet credited" });
}

// ---------- Router ----------

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    // Remove /api prefix from edge function path
    const path = url.pathname.replace(/^\/api/, "");

    // ---------- Auth routes (no auth needed) ----------
    if (req.method === "POST" && path === "/auth/register") {
      return handleRegister(await req.json());
    }
    if (req.method === "POST" && path === "/auth/login") {
      return handleLogin(await req.json());
    }
    if (req.method === "POST" && path === "/auth/admin/login") {
      return handleAdminLogin(await req.json());
    }

    // ---------- Protected routes ----------
    const payload = await authenticate(req);
    if (!payload) return err("Unauthorized", 401);

    const userId = payload.userId as string;
    const isAdmin = payload.isAdmin as boolean;

    // User routes
    if (!isAdmin) {
      if (req.method === "GET" && path === "/user/dashboard") return handleDashboard(userId);
      if (req.method === "GET" && path === "/user/transactions") return handleTransactions(userId);
      if (req.method === "POST" && path === "/invest/create") return handleCreateInvestment(userId, await req.json());
      if (req.method === "POST" && path === "/payment/submit") return handleSubmitPayment(userId, await req.json());
      if (req.method === "GET" && path === "/referral") return handleReferral(userId);
      if (req.method === "POST" && path === "/withdraw/request") return handleWithdraw(userId, await req.json());
    }

    // Admin routes
    if (isAdmin) {
      if (req.method === "GET" && path === "/admin/overview") return handleAdminOverview();
      if (req.method === "GET" && path === "/admin/users") return handleAdminUsers();
      if (req.method === "PATCH" && path.match(/^\/admin\/users\/(.+)\/toggle-block$/)) {
        const uid = path.match(/^\/admin\/users\/(.+)\/toggle-block$/)![1];
        return handleToggleBlock(uid);
      }
      if (req.method === "GET" && path === "/admin/investments") return handleAdminInvestments();
      if (req.method === "PATCH" && path === "/admin/invest/confirm") return handleConfirmInvestment(await req.json());
      if (req.method === "GET" && path === "/admin/withdrawals") return handleAdminWithdrawals();
      if (req.method === "PATCH" && path === "/admin/withdraw/approve") return handleApproveWithdrawal(await req.json());
      if (req.method === "GET" && path === "/admin/payments") return handleAdminPayments();
      if (req.method === "PATCH" && path === "/admin/payment/confirm") return handleConfirmPayment(await req.json());
    }

    return err("Not found", 404);
  } catch (e: any) {
    console.error("API Error:", e);
    return err(e.message || "Internal server error", 500);
  }
});
