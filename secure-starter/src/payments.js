// A9 Payment abuse — server-side state machine, maker-checker, KYC, ceilings BEFORE the transfer.
async function disburse(payment, actor, gateway) {
  if (payment.state !== 'APPROVED')        throw new Error('not approved');
  if (!payment.kycVerified)                throw new Error('kyc required');
  if (payment.makerId === actor.id)        throw new Error('maker cannot approve own payment');
  if (payment.amount > actor.approvalLimit) throw new Error('over ceiling');
  return gateway.transfer(payment);        // only reached once every guard passes
}
module.exports = { disburse };
