// A4 IDOR — always check ownership after fetching by a request-supplied id.
async function getOrder(req, res) {
  const order = await Order.findById(req.params.id);
  if (!order || order.userId !== req.session.userId) return res.status(404).end();
  return res.json(order);
}
module.exports = { getOrder };
