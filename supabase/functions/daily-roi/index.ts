import { MongoClient, ObjectId } from "npm:mongodb@6.12.0";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

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

// ⏱ ROI interval (10 minutes for testing)
const ROI_INTERVAL_MS = 10 * 60 * 1000;

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const db = await getDb();
    const investments = db.collection("investments");
    const users = db.collection("users");

    const now = new Date();

    const activeInvestments = await investments
      .find({
        status: "confirmed",
        paymentConfirmed: true,
        roiDaysCompleted: { $lt: 5 },
      })
      .toArray();

    let processed = 0;

    for (const inv of activeInvestments) {
      const daysCompleted = inv.roiDaysCompleted || 0;
      const lastRoiAt = inv.lastRoiAt
        ? new Date(inv.lastRoiAt)
        : null;

      // ⛔ Skip if ROI already given within the interval
      if (lastRoiAt && now.getTime() - lastRoiAt.getTime() < ROI_INTERVAL_MS) {
        continue;
      }

      const dailyReturn = inv.amount * 0.15; // 15% ROI

      const newDays = daysCompleted + 1;
      const isComplete = newDays >= 5;

      // Update investment
      await investments.updateOne(
        { _id: inv._id },
        {
          $set: {
            roiDaysCompleted: newDays,
            lastRoiAt: now,
            ...(isComplete
              ? { status: "completed", completedAt: now }
              : {}),
          },
        }
      );

      // Credit user
      await users.updateOne(
        { _id: new ObjectId(inv.userId) },
        {
          $inc: {
            walletBalance: dailyReturn,
            withdrawableBalance: dailyReturn,
          },
        }
      );

      if (isComplete) {
        await users.updateOne(
          { _id: new ObjectId(inv.userId) },
          { $inc: { activeInvestments: -1 } }
        );
      }

      processed++;
    }

    return new Response(
      JSON.stringify({
        message: `Processed ${processed} investments`,
        timestamp: now.toISOString(),
      }),
      {
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  } catch (e: any) {
    console.error("Daily ROI Error:", e);
    return new Response(
      JSON.stringify({ error: e.message }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
});
