import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, LoadingSpinner, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

const mockInvestments = [
  { id: "1", userName: "Adebayo Johnson", planName: "Gold Growth", amount: 10000, status: "pending" },
  { id: "2", userName: "Chioma Okafor", planName: "Platinum Growth", amount: 15000, status: "confirmed" },
  { id: "3", userName: "Emeka Uche", planName: "Starter Growth", amount: 2000, status: "pending" },
];

export default function AdminInvestments() {
  const [investments, setInvestments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAdminInvestments()
      .then((d: any) => setInvestments(d.investments || d))
      .catch(() => setInvestments(mockInvestments))
      .finally(() => setLoading(false));
  }, []);

  const confirm = async (id: string) => {
    try {
      await api.confirmInvestment(id);
      setInvestments((prev) => prev.map((inv) => inv.id === id ? { ...inv, status: "confirmed" } : inv));
      toast.success("Investment confirmed");
    } catch {
      setInvestments((prev) => prev.map((inv) => inv.id === id ? { ...inv, status: "confirmed" } : inv));
      toast.info("Investment confirmed (demo)");
    }
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  return (
    <DashboardLayout>
      <PageHeader title="Investments Management" subtitle="Review and confirm investments" />
      <div className="glass-card rounded-lg p-3 mb-6">
        <p className="text-xs text-muted-foreground">⏱ Confirm investments within 10–15 minutes of payment</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">User</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Plan</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Amount</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Status</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Action</th>
            </tr>
          </thead>
          <tbody>
            {investments.map((inv, i) => (
              <motion.tr key={inv.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }} className="border-b border-border/50 hover:bg-secondary/50 transition-colors">
                <td className="py-3 px-4 text-sm font-medium text-foreground">{inv.userName}</td>
                <td className="py-3 px-4 text-sm text-muted-foreground">{inv.planName}</td>
                <td className="py-3 px-4 text-sm text-foreground">₦{(inv.amount || 0).toLocaleString()}</td>
                <td className="py-3 px-4"><StatusBadge status={inv.status} /></td>
                <td className="py-3 px-4">
                  {inv.status === "pending" ? (
                    <button onClick={() => confirm(inv.id)} className="text-xs font-medium px-3 py-1.5 rounded-lg bg-success/10 text-success hover:bg-success/20 transition-all">
                      Confirm
                    </button>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
}
