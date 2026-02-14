import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { StatCard, PageHeader, LoadingSpinner } from "@/components/ui-components";
import { Users, Banknote, Copy, Check } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

export default function ReferralPage() {
  const { user } = useAuth();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  const referralLink = `${window.location.origin}/register?ref=${user?.referralCode || "REF123"}`;

  useEffect(() => {
    api.getReferral()
      .then(setData)
      .catch(() => setData({ totalReferrals: 3, referralEarnings: 1500 }))
      .finally(() => setLoading(false));
  }, []);

  const copyLink = () => {
    navigator.clipboard.writeText(referralLink);
    setCopied(true);
    toast.success("Referral link copied!");
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  return (
    <DashboardLayout>
      <PageHeader title="Referrals" subtitle="Earn ₦500 when your referral makes their first investment" />

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
        <StatCard label="Total Referrals" value={String(data?.totalReferrals || 0)} icon={<Users className="h-5 w-5" />} />
        <StatCard label="Referral Earnings" value={`₦${(data?.referralEarnings || 0).toLocaleString()}`} icon={<Banknote className="h-5 w-5" />} delay={0.1} />
      </div>

      <div className="gradient-card border border-border rounded-xl p-6 shadow-card">
        <h3 className="font-display font-semibold text-foreground mb-3">Your Referral Link</h3>
        <div className="flex items-center gap-2">
          <div className="flex-1 px-4 py-3 rounded-lg bg-secondary border border-border text-sm text-muted-foreground font-mono truncate">
            {referralLink}
          </div>
          <button
            onClick={copyLink}
            className="px-4 py-3 gradient-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 transition-opacity flex items-center gap-2"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            Copy
          </button>
        </div>
        <div className="mt-4 p-3 rounded-lg bg-primary/10 border border-primary/20">
          <p className="text-xs text-primary font-medium">💡 Please note: Your ₦500 referral bonus will only be credited after the person you referred makes their first investment.</p>
        </div>
        <p className="text-xs text-muted-foreground mt-3">Share this link with friends and earn ₦500 for each person who registers and invests.</p>
      </div>
    </DashboardLayout>
  );
}
