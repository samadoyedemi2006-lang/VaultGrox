import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, LoadingSpinner, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

export default function AdminPayments() {
  const [payments, setPayments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAdminPayments()
      .then((d: any) => setPayments(Array.isArray(d) ? d : []))
      .catch(() => setPayments([]))
      .finally(() => setLoading(false));
  }, []);

  const confirm = async (id: string) => {
    try {
      await api.confirmPayment(id);
      setPayments((prev) => prev.map((p) => p.id === id ? { ...p, status: "confirmed" } : p));
      toast.success("Payment confirmed & wallet credited");
    } catch (err: any) {
      toast.error(err.message || "Failed to confirm");
    }
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  return (
    <DashboardLayout>
      <PageHeader title="Payments" subtitle="Review and confirm user payment proofs" />
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">User</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Amount</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Reference</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Status</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Action</th>
            </tr>
          </thead>
          <tbody>
            {payments.length === 0 && (
              <tr><td colSpan={5} className="py-8 text-center text-muted-foreground text-sm">No payments yet</td></tr>
            )}
            {payments.map((p, i) => (
              <motion.tr key={p.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }} className="border-b border-border/50 hover:bg-secondary/50 transition-colors">
                <td className="py-3 px-4 text-sm font-medium text-foreground">{p.userName}</td>
                <td className="py-3 px-4 text-sm text-foreground">₦{(p.amount || 0).toLocaleString()}</td>
                <td className="py-3 px-4 text-sm text-muted-foreground">{p.reference}</td>
                <td className="py-3 px-4"><StatusBadge status={p.status} /></td>
                <td className="py-3 px-4">
                  {p.status === "pending" ? (
                    <button onClick={() => confirm(p.id)} className="text-xs font-medium px-3 py-1.5 rounded-lg bg-success/10 text-success hover:bg-success/20 transition-all">
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
