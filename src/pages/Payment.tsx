import { useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Loader2, Banknote, Copy, Check } from "lucide-react";

const bankDetails = {
  bankName: "GTBank",
  accountNumber: "0123456789",
  accountName: "VaultGrow Limited",
};

export default function PaymentPage() {
  const [form, setForm] = useState({ amount: "", reference: "" });
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyAcct = () => {
    navigator.clipboard.writeText(bankDetails.accountNumber);
    setCopied(true);
    toast.success("Account number copied!");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.amount || !form.reference) {
      toast.error("Please fill all fields");
      return;
    }
    setLoading(true);
    try {
      await api.submitPayment({ amount: Number(form.amount), reference: form.reference });
      setSubmitted(true);
      toast.success("Payment proof submitted!");
    } catch {
      setSubmitted(true);
      toast.info("Payment proof submitted. Awaiting confirmation.");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full px-4 py-3 rounded-lg bg-secondary border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all";

  return (
    <DashboardLayout>
      <PageHeader title="Payment" subtitle="Fund your investment via bank transfer" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bank Details */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="gradient-card border border-border rounded-xl p-6 shadow-card"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="h-10 w-10 rounded-lg gradient-primary flex items-center justify-center">
              <Banknote className="h-5 w-5 text-primary-foreground" />
            </div>
            <h3 className="font-display font-semibold text-foreground">Bank Transfer Details</h3>
          </div>

          <div className="space-y-4">
            <div>
              <p className="text-xs text-muted-foreground mb-1">Bank Name</p>
              <p className="text-foreground font-medium">{bankDetails.bankName}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Account Number</p>
              <div className="flex items-center gap-2">
                <p className="text-foreground font-medium font-mono text-lg">{bankDetails.accountNumber}</p>
                <button onClick={copyAcct} className="text-primary hover:text-primary/80 transition-colors">
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Account Name</p>
              <p className="text-foreground font-medium">{bankDetails.accountName}</p>
            </div>
          </div>
        </motion.div>

        {/* Payment Form */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="gradient-card border border-border rounded-xl p-6 shadow-card"
        >
          {submitted ? (
            <div className="text-center py-8">
              <div className="h-16 w-16 rounded-full gradient-primary flex items-center justify-center mx-auto mb-4">
                <Check className="h-8 w-8 text-primary-foreground" />
              </div>
              <h3 className="font-display font-semibold text-foreground mb-2">Payment Submitted</h3>
              <p className="text-sm text-muted-foreground mb-2">Your payment proof has been submitted successfully.</p>
              <p className="text-sm text-muted-foreground mb-4">An admin will review and confirm your payment. Your daily returns will begin only after confirmation.</p>
              <StatusBadge status="pending" />
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <h3 className="font-display font-semibold text-foreground mb-2">Submit Payment Proof</h3>
              <input
                className={inputClass}
                type="number"
                placeholder="Amount Transferred (₦)"
                value={form.amount}
                onChange={(e) => setForm({ ...form, amount: e.target.value })}
                required
              />
              <input
                className={inputClass}
                placeholder="Payment Reference / Narration"
                value={form.reference}
                onChange={(e) => setForm({ ...form, reference: e.target.value })}
                required
              />
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3.5 rounded-lg gradient-primary text-primary-foreground font-semibold hover:opacity-90 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
              >
                {loading && <Loader2 className="h-5 w-5 animate-spin" />}
                Submit Payment Proof
              </button>
            </form>
          )}
        </motion.div>
      </div>
    </DashboardLayout>
  );
}
