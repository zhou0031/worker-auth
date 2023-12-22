import {error,json,Router} from 'itty-router'
import jwt from '@tsndr/cloudflare-worker-jwt'


const router = Router()

async function ipAuth(request, env) {
	const allowed_ipv4 = await env.allowed.get("ipv4");
	const allowed_ipv6 = await env.allowed.get("ipv6");
	const trueClientIp = request.headers.get("CF-Connecting-IP");
	if (trueClientIp !== allowed_ipv4 && trueClientIp !== allowed_ipv6)
	  return new Response("Invalid Request", { status: 403 });
  }

async function jwtAuth(request, env) {
	const authorizationHeader = await request.headers.get("Authorization");
	if (!authorizationHeader || !authorizationHeader.startsWith("Bearer "))
	  return new Response("Unauthorized: No Bearer token provided", { status: 401 });
	const token = authorizationHeader.split(" ")[1];
	try {
	  const valid = await jwt.verify(token, env.JWT_SECRET);
	  if (!valid)
		return new Response("Unauthorized: Invalid token", { status: 401 });
	} catch (e) {
	  return new Response("Unauthorized: Verification failed", { status: 401 });
	}

	const access_token = await env.allowed.get("access_token")
	if(token!==access_token)  return new Response("Unauthorized: Invalid token", { status: 401 });
	return new Response({ok:true})
  }


router.all("*", ipAuth, jwtAuth);

export default {
	async fetch(request, env, ctx) {
		return router.handle(request, env, ctx).then(json).catch(error);
	},
};
