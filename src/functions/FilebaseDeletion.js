import { app } from '@azure/functions';
import { ObjectManager } from '@filebase/sdk';
import crypto from 'crypto';


const S3_KEY = '3C9339E4E7934D6F0657';
const S3_SECRET = 'Ajm4tviqX34mPFWkLvUpi4GECa7SVArj04IEMqq8';
const bucketName = 'aura-viva01';
const SHOPIFY_WEBHOOK_SECRET = 'ad096f032c0cbd81fee56b8051d7810ccff15a160824618f398127e8d84ae131';

const objectManager = new ObjectManager(S3_KEY, S3_SECRET, { bucket: bucketName });

function verifyShopifyHmac(rawBody, receivedHmac) {
  if (!receivedHmac) return false;

  const computed = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody, 'utf8')
    .digest('base64');

  try {
    const a = Buffer.from(computed, 'utf8');
    const b = Buffer.from(receivedHmac, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function getHeader(req, name, fallback = 'unknown') {
  return req.headers.get(name) || req.headers.get(name.toLowerCase()) || fallback;
}

app.http('ShopifyRefundWebhook', {
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    // --- read raw body, verify HMAC ---
    const rawBody = await request.text();

    const hmacHeader =
      request.headers.get('X-Shopify-Hmac-Sha256') ||
      request.headers.get('x-shopify-hmac-sha256');

    if (!verifyShopifyHmac(rawBody, hmacHeader)) {
      const topic = getHeader(request, 'X-Shopify-Topic');
      const shopDomain = getHeader(request, 'X-Shopify-Shop-Domain');
      context.log(`🚫 HMAC verification failed for topic "${topic}" from "${shopDomain}".`);
      return { status: 401, body: 'Invalid HMAC' };
    }

    const topic = getHeader(request, 'X-Shopify-Topic');
    const shopDomain = getHeader(request, 'X-Shopify-Shop-Domain');
    context.log(`✅ HMAC verified. Topic: ${topic}, Shop: ${shopDomain}`);

    // parse JSON now that HMAC is verified
    let body;
    try {
      body = JSON.parse(rawBody);
    } catch (err) {
      context.log(`❌ JSON parse error: ${err?.message || err}`);
      return { status: 400, body: 'Invalid JSON' };
    }

    const order = body.order || body;
    const orderId = order.id;
    const financialStatus = order.financial_status;
    const lineItems = order.line_items;
    const refunds = order.refunds;

    if (!orderId || !lineItems) {
      context.log('❌ Invalid payload:', JSON.stringify(order));
      return { status: 400, body: 'Invalid payload' };
    }

    context.log(`🔍 Processing Order #${order.order_number} with financial_status: ${financialStatus}`);

    let objectsToDelete = [];

    if (financialStatus === 'refunded') {
      // FULL refund
      objectsToDelete = lineItems.map((item) => `${orderId}-${item.id}`);
    } else if (financialStatus === 'partially_refunded') {
      // PARTIAL refund
      if (Array.isArray(refunds) && refunds.length > 0) {
        for (const refund of refunds) {
          if (Array.isArray(refund.refund_line_items)) {
            for (const refundItem of refund.refund_line_items) {
              const lineItemId = refundItem.line_item_id;
              const objectKey = `${orderId}-${lineItemId}`;
              if (!objectsToDelete.includes(objectKey)) {
                objectsToDelete.push(objectKey);
              }
            }
          }
        }
      }
    } else {
      context.log(`ℹ️ No refund detected for Order #${order.order_number}.`);
      return { status: 200, body: 'No refund action required.' };
    }

    if (objectsToDelete.length === 0) {
      context.log('⚠️ No objects to delete.');
      return { status: 200, body: 'No refunded items found to delete.' };
    }

    const results = [];

    for (const objectKey of objectsToDelete) {
      try {
        await objectManager.delete(objectKey);
        context.log(`✅ Deleted ${objectKey}`);
        results.push({ object: objectKey, status: 'deleted' });
      } catch (err) {
        context.log(`❌ Failed to delete ${objectKey}: ${err?.message || err}`);
        results.push({ object: objectKey, status: 'error', error: err?.message || String(err) });
      }
    }

    return {
      status: 200,
      jsonBody: {
        message: 'Deletion process completed.',
        results,
      },
    };
  },
});