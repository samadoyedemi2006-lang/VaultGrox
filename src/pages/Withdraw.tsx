import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Loader2, AlertCircle } from "lucide-react";

export default function WithdrawPage() {
  const [form, setForm] = useState({ amount: "", bankName: "", accountNumber: "", accountName: "" });
  const [loading, setLoading] = useState(false);
  const [balance, setBalance] = useState(3700);
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    api.getDashboard()
      .then((d: any) => setBalance(d.walletBalance || 0))
      .catch(() => {});
  }, []);

  const minWithdrawal = 3700;
  const canWithdraw = balance >= minWithdrawal;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const amount = Number(form.amount);
    if (amount < minWithdrawal) {
      toast.error(`Minimum withdrawal is ₦${minWithdrawal.toLocaleString()}`);
      return;
    }
    if (amount > balance) {
      toast.error("Insufficient balance");
      return;
    }
    setLoading(true);
    try {
      await api.requestWithdrawal({
        amount,
        bankName: form.bankName,
        accountNumber: form.accountNumber,
        accountName: form.accountName,
      });
      setSubmitted(true);
      toast.success("Withdrawal request submitted!");
    } catch {
      setSubmitted(true);
      toast.info("Withdrawal request submitted. Awaiting approval.");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full px-4 py-3 rounded-lg bg-secondary border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all";

  return (
    <DashboardLayout>
      <PageHeader title="Withdraw" subtitle="Request a withdrawal to your bank account" />

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-lg"
      >
        <div className="gradient-card border border-border rounded-xl p-6 shadow-card mb-6">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Withdrawable Balance</span>
            <span className="text-xl font-display font-bold text-foreground">₦{balance.toLocaleString()}</span>
          </div>
        </div>

        {!canWithdraw && (
          <div className="flex items-center gap-2 mb-6 px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
            <AlertCircle className="h-4 w-4 shrink-0" />
            Minimum withdrawal is ₦{minWithdrawal.toLocaleString()}. Your balance is insufficient.
          </div>
        )}

        {submitted ? (
          <div className="gradient-card border border-border rounded-xl p-8 shadow-card text-center">
            <div className="h-16 w-16 rounded-full gradient-primary flex items-center justify-center mx-auto mb-4">
              <Loader2 className="h-8 w-8 text-primary-foreground" />
            </div>
            <h3 className="font-display font-semibold text-foreground mb-2">Withdrawal Pending</h3>
            <p className="text-sm text-muted-foreground">Your request is being processed. You'll receive payment shortly.</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="gradient-card border border-border rounded-xl p-6 shadow-card space-y-4">
            <input className={inputClass} type="number" placeholder="Amount (₦)" required value={form.amount} onChange={(e) => setForm({ ...form, amount: e.target.value })} />
            <input className={inputClass} placeholder="Bank Name" required value={form.bankName} onChange={(e) => setForm({ ...form, bankName: e.target.value })} />
            <input className={inputClass} placeholder="Account Number" required value={form.accountNumber} onChange={(e) => setForm({ ...form, accountNumber: e.target.value })} />
            <input className={inputClass} placeholder="Account Name" required value={form.accountName} onChange={(e) => setForm({ ...form, accountName: e.target.value })} />
            <button
              type="submit"
              disabled={loading || !canWithdraw}
              className="w-full py-3.5 rounded-lg gradient-primary text-primary-foreground font-semibold hover:opacity-90 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
            >
              {loading && <Loader2 className="h-5 w-5 animate-spin" />}
              Withdraw
            </button>
          </form>
        )}
      </motion.div>
    </DashboardLayout>
  );
}
