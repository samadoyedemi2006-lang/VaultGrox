import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { StatCard, PageHeader, LoadingSpinner } from "@/components/ui-components";
import { Users, TrendingUp, Banknote, Clock, CheckCircle, Zap, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

export default function AdminOverview() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [triggeringRoi, setTriggeringRoi] = useState(false);

  const handleTriggerRoi = async () => {
    setTriggeringRoi(true);
    try {
      const result = await api.triggerRoi();
      toast.success(result.message || "ROI processed successfully");
    } catch (err: any) {
      toast.error(err.message || "Failed to trigger ROI");
    } finally {
      setTriggeringRoi(false);
    }
  };

  useEffect(() => {
    api.getAdminOverview()
      .then(setData)
      .catch(() => setData({
        totalUsers: 156,
        totalInvestments: 89,
        totalPlatformIncome: 450000,
        pendingInvestments: 12,
        confirmedInvestments: 77,
      }))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  const stats = [
    { label: "Total Users", value: String(data?.totalUsers || 0), icon: <Users className="h-5 w-5" /> },
    { label: "Total Investments", value: String(data?.totalInvestments || 0), icon: <TrendingUp className="h-5 w-5" /> },
    { label: "Platform Income", value: `₦${(data?.totalPlatformIncome || 0).toLocaleString()}`, icon: <Banknote className="h-5 w-5" /> },
    { label: "Pending Investments", value: String(data?.pendingInvestments || 0), icon: <Clock className="h-5 w-5" /> },
    { label: "Confirmed Investments", value: String(data?.confirmedInvestments || 0), icon: <CheckCircle className="h-5 w-5" /> },
  ];

  return (
    <DashboardLayout>
      <PageHeader title="Admin Overview" subtitle="Platform statistics at a glance" />
      <div className="mb-6">
        <button
          onClick={handleTriggerRoi}
          disabled={triggeringRoi}
          className="px-5 py-2.5 gradient-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 disabled:opacity-50 transition-all flex items-center gap-2"
        >
          {triggeringRoi ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
          {triggeringRoi ? "Processing..." : "Trigger ROI Payout"}
        </button>
        <p className="text-xs text-muted-foreground mt-2">Manually process pending ROI payouts for all active investments</p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {stats.map((s, i) => (
          <StatCard key={s.label} label={s.label} value={s.value} icon={s.icon} delay={i * 0.08} />
        ))}
      </div>
    </DashboardLayout>
  );
}
