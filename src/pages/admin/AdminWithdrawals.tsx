import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, LoadingSpinner, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

const mockWithdrawals = [
  { id: "1", userName: "Adebayo Johnson", amount: 5000, bankName: "GTBank", accountNumber: "0123456789", accountName: "Adebayo Johnson", status: "pending" },
  { id: "2", userName: "Chioma Okafor", amount: 8000, bankName: "Access Bank", accountNumber: "9876543210", accountName: "Chioma Okafor", status: "paid" },
];

export default function AdminWithdrawals() {
  const [withdrawals, setWithdrawals] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAdminWithdrawals()
      .then((d: any) => setWithdrawals(d.withdrawals || d))
      .catch(() => setWithdrawals(mockWithdrawals))
      .finally(() => setLoading(false));
  }, []);

  const approve = async (id: string) => {
    try {
      await api.approveWithdrawal(id);
      setWithdrawals((prev) => prev.map((w) => w.id === id ? { ...w, status: "paid" } : w));
      toast.success("Withdrawal approved");
    } catch {
      setWithdrawals((prev) => prev.map((w) => w.id === id ? { ...w, status: "paid" } : w));
      toast.info("Withdrawal approved (demo)");
    }
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  return (
    <DashboardLayout>
      <PageHeader title="Withdrawal Requests" subtitle="Review and approve withdrawal requests" />
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">User</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Amount</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Bank</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Account</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Status</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Action</th>
            </tr>
          </thead>
          <tbody>
            {withdrawals.map((w, i) => (
              <motion.tr key={w.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }} className="border-b border-border/50 hover:bg-secondary/50 transition-colors">
                <td className="py-3 px-4 text-sm font-medium text-foreground">{w.userName}</td>
                <td className="py-3 px-4 text-sm text-foreground">₦{(w.amount || 0).toLocaleString()}</td>
                <td className="py-3 px-4 text-sm text-muted-foreground">{w.bankName}</td>
                <td className="py-3 px-4">
                  <div className="text-sm text-foreground">{w.accountNumber}</div>
                  <div className="text-xs text-muted-foreground">{w.accountName}</div>
                </td>
                <td className="py-3 px-4"><StatusBadge status={w.status} /></td>
                <td className="py-3 px-4">
                  {w.status === "pending" ? (
                    <button onClick={() => approve(w.id)} className="text-xs font-medium px-3 py-1.5 rounded-lg bg-success/10 text-success hover:bg-success/20 transition-all">
                      Approve
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
