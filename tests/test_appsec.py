"""pah appsec: the fourteen holes AI-built web apps ship with, each as a vulnerable case and its fixed twin.

Keys and tokens are assembled at run time from a seeded generator, so no key-shaped string sits in this file.
"""
from __future__ import annotations

import base64
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pah import appsec  # noqa: E402
from pah.model import rank  # noqa: E402


def fake_key(prefix: str, n: int = 64, seed: int = 7) -> str:
    rnd = random.Random(seed)
    return prefix + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))


def b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def service_role_jwt() -> str:
    head = b64url({"alg": "HS256", "typ": "JWT"})
    body = b64url({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "service_role", "iat": 1700000000,
                   "exp": 2000000000})
    return f"{head}.{body}.{fake_key('', 43, seed=3)}"


def run(files: dict, **kw):
    return appsec.check_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}, **kw)


def found(files: dict, at_least: str = "medium", **kw) -> dict:
    """{rule: worst severity} for findings at or above `at_least`."""
    out: dict[str, str] = {}
    for f in run(files, **kw).findings:
        if rank(f.severity) >= rank(at_least) and rank(f.severity) > rank(out.get(f.rule, "info")):
            out[f.rule] = f.severity
    return out


class Case(unittest.TestCase):
    def hit(self, rule: str, files: dict, severity: str = "medium", **kw):
        got = found(files, **kw)
        self.assertIn(rule, got, f"{rule} not reported; got {got}")
        self.assertGreaterEqual(rank(got[rule]), rank(severity), f"{rule} reported as {got[rule]}, wanted {severity}")

    def clean(self, rule: str, files: dict, **kw):
        got = found(files, **kw)
        self.assertNotIn(rule, got, f"{rule} reported on the fixed version: {got}")


class XssTest(Case):  # 1. Script in your username
    def test_react_html_from_user_profile(self):
        self.hit("PAH-W001", {"components/Profile.tsx": """
            export function Profile({ user }) {
              return <div className="bio" dangerouslySetInnerHTML={{ __html: user.bio }} />;
            }
        """})

    def test_react_html_sanitized(self):
        self.clean("PAH-W001", {"components/Profile.tsx": """
            import DOMPurify from "dompurify";
            export function Profile({ user }) {
              return <div className="bio" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />;
            }
        """})

    def test_express_echoes_query_into_html(self):
        self.hit("PAH-W001", {"server.js": """
            app.get("/hello", (req, res) => {
              res.send(`<h1>Hello ${req.query.name}</h1>`);
            });
        """}, "high")

    def test_express_escapes_query(self):
        self.clean("PAH-W001", {"server.js": """
            app.get("/hello", (req, res) => {
              res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
            });
        """})

    def test_flask_template_string_from_request(self):
        self.hit("PAH-W001", {"app.py": """
            @app.route("/search")
            def search():
                return render_template_string(f"<p>Results for {request.args.get('q')}</p>")
        """}, "high")

    def test_flask_template_file(self):
        self.clean("PAH-W001", {"app.py": """
            @app.route("/search")
            def search():
                return render_template("search.html", q=request.args.get("q"))
        """})

    def test_jinja_safe_filter(self):
        self.hit("PAH-W001", {"templates/profile.html": "<p>{{ user.bio | safe }}</p>\n"})

    def test_jinja_escaped(self):
        self.clean("PAH-W001", {"templates/profile.html": "<p>{{ user.bio }}</p>\n"})

    def test_inner_html_from_data(self):
        self.hit("PAH-W001", {"public/comments.js": "el.innerHTML = comment.text;\n"})

    def test_text_content_and_literal_html(self):
        self.clean("PAH-W001", {"public/comments.js": "el.textContent = comment.text;\nbox.innerHTML = '<b>hi</b>';\n"})


class IdorTest(Case):  # 2. Change the ID in the URL
    def test_next_route_reads_any_order(self):
        self.hit("PAH-W002", {"app/api/orders/[id]/route.ts": """
            import { auth } from "@/auth";
            import { db } from "@/lib/db";
            export async function GET(req: Request, { params }: { params: { id: string } }) {
              const session = await auth();
              if (!session) return new Response("Unauthorized", { status: 401 });
              const order = await db.order.findUnique({ where: { id: params.id } });
              return Response.json(order);
            }
        """})

    def test_next_route_scoped_to_owner(self):
        self.clean("PAH-W002", {"app/api/orders/[id]/route.ts": """
            import { auth } from "@/auth";
            import { db } from "@/lib/db";
            export async function GET(req: Request, { params }: { params: { id: string } }) {
              const session = await auth();
              if (!session) return new Response("Unauthorized", { status: 401 });
              const order = await db.order.findFirst({ where: { id: params.id, userId: session.user.id } });
              return Response.json(order);
            }
        """})

    def test_express_deletes_any_note(self):
        self.hit("PAH-W002", {"routes/notes.js": """
            router.delete("/notes/:id", requireAuth, async (req, res) => {
              await Note.findByIdAndDelete(req.params.id);
              res.sendStatus(204);
            });
        """}, "high")

    def test_express_deletes_own_note(self):
        self.clean("PAH-W002", {"routes/notes.js": """
            router.delete("/notes/:id", requireAuth, async (req, res) => {
              await Note.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
              res.sendStatus(204);
            });
        """})

    def test_public_product_by_id_is_fine(self):
        self.clean("PAH-W002", {"server.js": """
            app.get("/products/:id", async (req, res) => {
              res.json(await Product.findById(req.params.id));
            });
        """})

    def test_flask_invoice_by_id(self):
        self.hit("PAH-W002", {"app.py": """
            @app.route("/invoices/<int:invoice_id>")
            @login_required
            def invoice(invoice_id):
                inv = Invoice.query.get_or_404(invoice_id)
                return jsonify(inv.to_dict())
        """})

    def test_flask_invoice_scoped(self):
        self.clean("PAH-W002", {"app.py": """
            @app.route("/invoices/<int:invoice_id>")
            @login_required
            def invoice(invoice_id):
                inv = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
                return jsonify(inv.to_dict())
        """})

    def test_drf_viewset_without_queryset_filter(self):
        self.hit("PAH-W002", {"orders/views.py": """
            class OrderViewSet(viewsets.ModelViewSet):
                queryset = Order.objects.all()
                serializer_class = OrderSerializer
                permission_classes = [IsAuthenticated]
        """})

    def test_drf_viewset_filtered_by_user(self):
        self.clean("PAH-W002", {"orders/views.py": """
            class OrderViewSet(viewsets.ModelViewSet):
                serializer_class = OrderSerializer
                permission_classes = [IsAuthenticated]

                def get_queryset(self):
                    return Order.objects.filter(user=self.request.user)
        """})


class AdminTest(Case):  # 3. Type /admin
    def test_express_admin_route_open(self):
        self.hit("PAH-W003", {"server.js": """
            app.get("/admin/users", async (req, res) => {
              res.json(await User.find());
            });
        """}, "high")

    def test_express_admin_route_checks_role(self):
        self.clean("PAH-W003", {"server.js": """
            app.get("/admin/users", requireAdmin, async (req, res) => {
              res.json(await User.find());
            });
        """})

    def test_express_admin_route_signed_in_only(self):
        got = found({"server.js": """
            app.get("/admin/users", requireAuth, async (req, res) => {
              res.json(await User.find());
            });
        """})
        self.assertEqual(got.get("PAH-W003"), "medium")

    def test_express_admin_router_mounted_open(self):
        self.hit("PAH-W003", {"server.js": 'app.use("/admin", adminRouter);\n'}, "high")

    def test_express_admin_router_mounted_with_guard(self):
        self.clean("PAH-W003", {"server.js": 'app.use("/admin", requireAdmin, adminRouter);\n'})

    def test_next_admin_api_open(self):
        self.hit("PAH-W003", {"app/api/admin/users/route.ts": """
            import { db } from "@/lib/db";
            export async function GET() {
              return Response.json(await db.user.findMany());
            }
        """}, "high")

    def test_next_admin_api_checks_role(self):
        self.clean("PAH-W003", {"app/api/admin/users/route.ts": """
            import { auth } from "@/auth";
            import { db } from "@/lib/db";
            export async function GET() {
              const session = await auth();
              if (session?.user?.role !== "admin") return new Response("Forbidden", { status: 403 });
              return Response.json(await db.user.findMany());
            }
        """})

    def test_next_admin_page_server_component_reads_db(self):
        self.hit("PAH-W003", {"app/admin/page.tsx": """
            import { db } from "@/lib/db";
            export default async function AdminPage() {
              const users = await db.user.findMany();
              return <UserTable users={users} />;
            }
        """}, "high")

    def test_next_admin_page_behind_middleware(self):
        self.clean("PAH-W003", {
            "app/admin/page.tsx": """
                import { db } from "@/lib/db";
                export default async function AdminPage() {
                  const users = await db.user.findMany();
                  return <UserTable users={users} />;
                }
            """,
            "middleware.ts": """
                export async function middleware(req) {
                  const token = await getToken({ req });
                  if (req.nextUrl.pathname.startsWith("/admin") && token?.role !== "admin") {
                    return NextResponse.redirect(new URL("/", req.url));
                  }
                }
                export const config = { matcher: ["/admin/:path*"] };
            """})

    def test_flask_admin_open(self):
        self.hit("PAH-W003", {"app.py": """
            @app.route("/admin")
            def admin():
                return render_template("admin.html", users=User.query.all())
        """}, "high")

    def test_flask_admin_decorated(self):
        self.clean("PAH-W003", {"app.py": """
            @app.route("/admin")
            @admin_required
            def admin():
                return render_template("admin.html", users=User.query.all())
        """})

    def test_flask_admin_blueprint_with_before_request(self):
        self.clean("PAH-W003", {"admin.py": """
            admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

            @admin_bp.before_request
            def only_admins():
                if not current_user.is_admin:
                    abort(403)

            @admin_bp.route("/users")
            def users():
                return jsonify([u.to_dict() for u in User.query.all()])
        """})

    def test_flask_admin_blueprint_open(self):
        self.hit("PAH-W003", {"admin.py": """
            admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

            @admin_bp.route("/users")
            def users():
                return jsonify([u.to_dict() for u in User.query.all()])
        """}, "high")


class BrowserKeyTest(Case):  # 4. API key in the browser
    def test_openai_in_browser(self):
        self.hit("PAH-W004", {"src/lib/ai.ts": """
            import OpenAI from "openai";
            export const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
        """}, "high")

    def test_openai_on_server(self):
        self.clean("PAH-W004", {"app/api/chat/route.ts": """
            import OpenAI from "openai";
            const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        """})

    def test_service_role_env_in_vite_app(self):
        self.hit("PAH-W004", {"package.json": '{"devDependencies": {"vite": "^6.0.0"}}',
                              "src/lib/supabase.ts": """
            import { createClient } from "@supabase/supabase-js";
            export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);
        """}, "high")

    def test_anon_key_in_vite_app(self):
        self.clean("PAH-W004", {"package.json": '{"devDependencies": {"vite": "^6.0.0"}}',
                                "src/lib/supabase.ts": """
            import { createClient } from "@supabase/supabase-js";
            export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
        """})

    def test_literal_key_in_client_component(self):
        key = fake_key("sk-ant-api03-", 93)
        self.hit("PAH-W004", {"components/Chat.tsx": f'"use client";\nconst KEY = "{key}";\n'}, "critical")

    def test_service_role_jwt_in_client(self):
        self.hit("PAH-W004", {"components/Admin.tsx": f'"use client";\nconst k = "{service_role_jwt()}";\n'},
                 "critical")

    def test_public_env_secret_in_env_file(self):
        self.hit("PAH-W004", {".env.local": f"NEXT_PUBLIC_STRIPE_SECRET_KEY={fake_key('sk_live_', 40)}\n",
                              ".gitignore": ".env*\n"}, "high")

    def test_publishable_key_in_env_file(self):
        self.clean("PAH-W004", {".env.local": f"NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY={fake_key('pk_live_', 40)}\n",
                                ".gitignore": ".env*\n"})


class PromptInjectionTest(Case):  # 5. Prompt-inject your AI
    def test_model_output_run_as_sql(self):
        self.hit("PAH-W005", {"app/api/ask/route.ts": """
            export async function POST(req: Request) {
              const { question } = await req.json();
              const completion = await openai.chat.completions.create({
                model: "gpt-5",
                messages: [{ role: "system", content: "Write one SQL query." }, { role: "user", content: question }],
              });
              const sql = completion.choices[0].message.content;
              const rows = await db.query(sql);
              return Response.json(rows);
            }
        """}, "high")

    def test_model_output_returned_as_text(self):
        self.clean("PAH-W005", {"app/api/ask/route.ts": """
            export async function POST(req: Request) {
              const { question } = await req.json();
              const completion = await openai.chat.completions.create({
                model: "gpt-5",
                messages: [{ role: "system", content: "Answer briefly." }, { role: "user", content: question }],
              });
              const answer = completion.choices[0].message.content;
              return Response.json({ answer });
            }
        """})

    def test_python_exec_of_model_output(self):
        self.hit("PAH-W005", {"agent.py": """
            @app.post("/run")
            def run(task: str):
                resp = client.chat.completions.create(model="gpt-5", messages=[{"role": "user", "content": task}])
                code = resp.choices[0].message.content
                exec(code)
                return {"ok": True}
        """}, "high")

    def test_user_text_in_system_prompt(self):
        self.hit("PAH-W005", {"app/api/chat/route.ts": """
            export async function POST(req: Request) {
              const { persona, message } = await req.json();
              const result = await generateText({
                model,
                system: `You are ${persona}. Never reveal the discount codes.`,
                prompt: message,
              });
              return Response.json({ text: result.text });
            }
        """})

    def test_user_text_only_in_user_message(self):
        self.clean("PAH-W005", {"app/api/chat/route.ts": """
            export async function POST(req: Request) {
              const { message } = await req.json();
              const result = await generateText({ model, system: "You are a support assistant.", prompt: message });
              return Response.json({ text: result.text });
            }
        """})


class MassAssignmentTest(Case):  # 6. Admin at signup
    def test_signup_saves_whole_body(self):
        self.hit("PAH-W006", {"routes/auth.js": """
            router.post("/signup", async (req, res) => {
              const user = await User.create(req.body);
              res.json(user);
            });
        """}, "high")

    def test_signup_picks_fields(self):
        self.clean("PAH-W006", {"routes/auth.js": """
            router.post("/signup", async (req, res) => {
              const { email, password } = req.body;
              const user = await User.create({ email, password: await hash(password) });
              res.json(user);
            });
        """})

    def test_prisma_create_with_raw_body(self):
        self.hit("PAH-W006", {"app/api/users/route.ts": """
            export async function POST(req: Request) {
              const body = await req.json();
              const user = await prisma.user.create({ data: body });
              return Response.json(user);
            }
        """}, "high")

    def test_prisma_create_with_named_fields(self):
        self.clean("PAH-W006", {"app/api/users/route.ts": """
            export async function POST(req: Request) {
              const body = await req.json();
              const user = await prisma.user.create({ data: { email: body.email, name: body.name } });
              return Response.json(user);
            }
        """})

    def test_role_from_request(self):
        self.hit("PAH-W006", {"app/api/profile/route.ts": """
            export async function PATCH(req: Request) {
              const session = await auth();
              const body = await req.json();
              await prisma.user.update({ where: { id: session.user.id }, data: { name: body.name, role: body.role } });
              return new Response(null, { status: 204 });
            }
        """}, "high")

    def test_python_model_from_request_json(self):
        self.hit("PAH-W006", {"app.py": """
            @app.post("/register")
            def register():
                user = User(**request.json)
                db.session.add(user)
                db.session.commit()
                return jsonify(user.to_dict())
        """}, "high")

    def test_python_model_with_named_fields(self):
        self.clean("PAH-W006", {"app.py": """
            @app.post("/register")
            def register():
                data = request.get_json()
                user = User(email=data["email"], name=data["name"])
                db.session.add(user)
                db.session.commit()
                return jsonify(user.to_dict())
        """})

    def test_supabase_role_in_user_metadata(self):
        self.hit("PAH-W006", {"lib/guard.ts": 'export const isAdmin = (user) => user.user_metadata.role === "admin";\n'},
                 "high")

    def test_supabase_role_in_app_metadata(self):
        self.clean("PAH-W006", {"lib/guard.ts": 'export const isAdmin = (user) => user.app_metadata.role === "admin";\n'})


class PriceTest(Case):  # 7. Edit the price
    def test_stripe_price_from_cart(self):
        self.hit("PAH-W007", {"app/api/checkout/route.ts": """
            export async function POST(req: Request) {
              const { items } = await req.json();
              const session = await stripe.checkout.sessions.create({
                mode: "payment",
                line_items: items.map((item) => ({
                  price_data: { currency: "usd", product_data: { name: item.name }, unit_amount: item.price * 100 },
                  quantity: 1,
                })),
                success_url: `${origin}/success`,
              });
              return Response.json({ url: session.url });
            }
        """}, "high")

    def test_stripe_price_looked_up(self):
        self.clean("PAH-W007", {"app/api/checkout/route.ts": """
            export async function POST(req: Request) {
              const { items } = await req.json();
              const session = await stripe.checkout.sessions.create({
                mode: "payment",
                line_items: items.map((item) => ({ price: PRICE_IDS[item.id], quantity: 1 })),
                success_url: `${origin}/success`,
              });
              return Response.json({ url: session.url });
            }
        """})

    def test_python_charge_amount_from_request(self):
        self.hit("PAH-W007", {"payments.py": """
            @app.post("/pay")
            def pay():
                data = request.get_json()
                intent = stripe.PaymentIntent.create(amount=int(data["price"] * 100), currency="usd")
                return jsonify(client_secret=intent.client_secret)
        """}, "high")

    def test_python_charge_amount_from_catalog(self):
        self.clean("PAH-W007", {"payments.py": """
            @app.post("/pay")
            def pay():
                data = request.get_json()
                product = Product.query.get_or_404(data["product_id"])
                intent = stripe.PaymentIntent.create(amount=product.price_cents, currency="usd")
                return jsonify(client_secret=intent.client_secret)
        """})


class FakePaymentTest(Case):  # 8. Fake a payment
    def test_webhook_without_signature(self):
        self.hit("PAH-W008", {"app/api/webhooks/stripe/route.ts": """
            export async function POST(req: Request) {
              const event = await req.json();
              if (event.type === "checkout.session.completed") {
                await db.order.update({ where: { id: event.data.object.metadata.orderId }, data: { status: "paid" } });
              }
              return new Response("ok");
            }
        """}, "high")

    def test_webhook_with_signature(self):
        self.clean("PAH-W008", {"app/api/webhooks/stripe/route.ts": """
            export async function POST(req: Request) {
              const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature")!,
                                                           process.env.STRIPE_WEBHOOK_SECRET!);
              if (event.type === "checkout.session.completed") {
                await db.order.update({ where: { id: event.data.object.metadata.orderId }, data: { status: "paid" } });
              }
              return new Response("ok");
            }
        """})

    def test_success_page_unlocks_pro(self):
        self.hit("PAH-W008", {"app/success/page.tsx": """
            export default async function Success({ searchParams }) {
              await db.user.update({ where: { id: searchParams.uid }, data: { isPro: true } });
              return <p>Thanks!</p>;
            }
        """}, "high")

    def test_success_page_checks_with_stripe(self):
        self.clean("PAH-W008", {"app/success/page.tsx": """
            export default async function Success({ searchParams }) {
              const s = await stripe.checkout.sessions.retrieve(searchParams.session_id);
              if (s.payment_status === "paid") {
                await db.user.update({ where: { id: s.client_reference_id }, data: { isPro: true } });
              }
              return <p>Thanks!</p>;
            }
        """})

    def test_browser_marks_itself_paid(self):
        self.hit("PAH-W008", {"components/Upgrade.tsx": """
            "use client";
            export function Upgrade({ user }) {
              async function done() {
                await supabase.from("profiles").update({ is_pro: true }).eq("id", user.id);
              }
              return <PayButton onSuccess={done} />;
            }
        """}, "high")

    def test_browser_only_reads_status(self):
        self.clean("PAH-W008", {"components/Upgrade.tsx": """
            "use client";
            export function Upgrade({ user }) {
              const { data } = useQuery(() => supabase.from("profiles").select("is_pro").eq("id", user.id));
              return data?.is_pro ? <Pro /> : <PayButton />;
            }
        """})


class RaceTest(Case):  # 9. Redeem it 100 times
    def test_coupon_check_then_update(self):
        self.hit("PAH-W009", {"app/api/redeem/route.ts": """
            export async function POST(req: Request) {
              const { code } = await req.json();
              const coupon = await prisma.coupon.findUnique({ where: { code } });
              if (!coupon || coupon.used) return new Response("invalid", { status: 400 });
              await prisma.user.update({ where: { id: userId }, data: { credits: { increment: coupon.value } } });
              await prisma.coupon.update({ where: { code }, data: { used: true } });
              return new Response("ok");
            }
        """})

    def test_coupon_conditional_update(self):
        self.clean("PAH-W009", {"app/api/redeem/route.ts": """
            export async function POST(req: Request) {
              const { code } = await req.json();
              const claimed = await prisma.coupon.updateMany({ where: { code, used: false }, data: { used: true } });
              if (claimed.count === 0) return new Response("invalid", { status: 400 });
              await prisma.user.update({ where: { id: userId }, data: { credits: { increment: 10 } } });
              return new Response("ok");
            }
        """})

    def test_django_coupon_get_then_save(self):
        self.hit("PAH-W009", {"shop/views.py": """
            def redeem(request):
                coupon = Coupon.objects.get(code=request.POST["code"])
                if coupon.used:
                    return HttpResponseBadRequest("used")
                coupon.used = True
                coupon.save()
                request.user.profile.credits += coupon.value
                request.user.profile.save()
                return HttpResponse("ok")
        """})

    def test_django_coupon_filter_update(self):
        self.clean("PAH-W009", {"shop/views.py": """
            def redeem(request):
                updated = Coupon.objects.filter(code=request.POST["code"], used=False).update(used=True)
                if not updated:
                    return HttpResponseBadRequest("used")
                Profile.objects.filter(user=request.user).update(credits=F("credits") + 10)
                return HttpResponse("ok")
        """})


class QuantityTest(Case):  # 10. Order -1 items
    def test_negative_quantity_into_total(self):
        self.hit("PAH-W010", {"app/api/orders/route.ts": """
            export async function POST(req: Request) {
              const { productId, quantity } = await req.json();
              const product = await db.product.findUnique({ where: { id: productId } });
              const total = product.price * quantity;
              await db.order.create({ data: { productId, quantity, total } });
              return new Response("ok");
            }
        """}, "high")

    def test_quantity_bounded(self):
        self.clean("PAH-W010", {"app/api/orders/route.ts": """
            export async function POST(req: Request) {
              const { productId, quantity } = await req.json();
              if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
                return new Response("bad quantity", { status: 400 });
              }
              const product = await db.product.findUnique({ where: { id: productId } });
              const total = product.price * quantity;
              await db.order.create({ data: { productId, quantity, total } });
              return new Response("ok");
            }
        """})

    def test_zod_quantity_any_number(self):
        self.hit("PAH-W010", {"lib/schemas.ts": 'export const Item = z.object({ productId: z.string(), quantity: z.number() });\n'})

    def test_zod_quantity_positive(self):
        self.clean("PAH-W010", {"lib/schemas.ts": 'export const Item = z.object({ productId: z.string(), quantity: z.number().int().positive() });\n'})

    def test_pydantic_quantity_plain_int(self):
        self.hit("PAH-W010", {"schemas.py": "class CartItem(BaseModel):\n    product_id: int\n    quantity: int\n"})

    def test_pydantic_quantity_bounded(self):
        self.clean("PAH-W010", {"schemas.py": "class CartItem(BaseModel):\n    product_id: int\n    quantity: int = Field(gt=0, le=100)\n"})


class LoginCodeTest(Case):  # 11. Guess the login code
    def test_code_check_without_limit(self):
        self.hit("PAH-W011", {"app/api/auth/verify/route.ts": """
            export async function POST(req: Request) {
              const { email, code } = await req.json();
              const row = await db.loginCode.findFirst({ where: { email } });
              if (!row || row.code !== code) return new Response("wrong code", { status: 401 });
              return createSession(email);
            }
        """}, "high")

    def test_code_check_with_rate_limit(self):
        self.clean("PAH-W011", {"app/api/auth/verify/route.ts": """
            import { ratelimit } from "@/lib/ratelimit";
            export async function POST(req: Request) {
              const { email, code } = await req.json();
              const { success } = await ratelimit.limit(email);
              if (!success) return new Response("too many attempts", { status: 429 });
              const row = await db.loginCode.findFirst({ where: { email } });
              if (!row || row.code !== code) return new Response("wrong code", { status: 401 });
              return createSession(email);
            }
        """})

    def test_code_from_math_random(self):
        self.hit("PAH-W011", {"lib/otp.ts": "export const newCode = () => { const code = Math.floor(100000 + Math.random() * 900000).toString(); return code; };\n"}, "high")

    def test_code_from_crypto(self):
        self.clean("PAH-W011", {"lib/otp.ts": 'import { randomInt } from "crypto";\nexport const newCode = () => randomInt(100000, 1000000).toString();\n'})

    def test_python_random_otp(self):
        self.hit("PAH-W011", {"auth.py": "import random\n\ndef make_otp():\n    otp = random.randint(1000, 9999)\n    return otp\n"}, "high")

    def test_python_secrets_otp(self):
        self.clean("PAH-W011", {"auth.py": "import secrets\n\ndef make_otp():\n    otp = secrets.randbelow(900000) + 100000\n    return otp\n"})


class DatabaseTest(Case):  # 12. Query your database
    def test_sql_built_from_template(self):
        self.hit("PAH-W012", {"lib/users.js": "export const byEmail = (email) => pool.query(`SELECT * FROM users WHERE email = '${email}'`);\n"}, "high")

    def test_sql_with_parameters(self):
        self.clean("PAH-W012", {"lib/users.js": 'export const byEmail = (email) => pool.query("SELECT * FROM users WHERE email = $1", [email]);\n'})

    def test_sql_tagged_template_is_safe(self):
        self.clean("PAH-W012", {"lib/users.js": "export const byEmail = (email) => sql`SELECT * FROM users WHERE email = ${email}`;\n"})

    def test_prisma_raw_unsafe(self):
        self.hit("PAH-W012", {"lib/users.ts": "export const byId = (id) => prisma.$queryRawUnsafe(`SELECT * FROM \"User\" WHERE id = ${id}`);\n"}, "high")

    def test_python_fstring_sql(self):
        self.hit("PAH-W012", {"db.py": "def find(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"}, "high")

    def test_python_percent_sql(self):
        self.hit("PAH-W012", {"db.py": "def find(cur, name):\n    cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"}, "high")

    def test_python_parameters(self):
        self.clean("PAH-W012", {"db.py": "def find(cur, name):\n    cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))\n"})

    def test_supabase_table_without_rls(self):
        self.hit("PAH-W012", {"supabase/migrations/0001_init.sql": """
            create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid, body text);
        """}, "high")

    def test_supabase_table_with_rls(self):
        self.clean("PAH-W012", {"supabase/migrations/0001_init.sql": """
            create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid, body text);
            alter table public.notes enable row level security;
            create policy "own notes" on public.notes for all using (auth.uid() = user_id);
        """})

    def test_supabase_policy_true_for_all(self):
        self.hit("PAH-W012", {"supabase/migrations/0001_init.sql": """
            create table public.notes (id uuid primary key, user_id uuid, body text);
            alter table public.notes enable row level security;
            create policy "anyone" on public.notes for all using (true);
        """}, "high")

    def test_firestore_test_mode(self):
        self.hit("PAH-W012", {"firestore.rules": """
            rules_version = '2';
            service cloud.firestore {
              match /databases/{database}/documents {
                match /{document=**} {
                  allow read, write: if request.time < timestamp.date(2026, 12, 1);
                }
              }
            }
        """}, "high")

    def test_firestore_owner_rules(self):
        self.clean("PAH-W012", {"firestore.rules": """
            rules_version = '2';
            service cloud.firestore {
              match /databases/{database}/documents {
                match /users/{userId} {
                  allow read, write: if request.auth != null && request.auth.uid == userId;
                }
              }
            }
        """})

    def test_realtime_database_open(self):
        self.hit("PAH-W012", {"database.rules.json": '{"rules": {".read": true, ".write": true}}'}, "high")


class EnvInGitTest(Case):  # 13. .env in Git
    def secret_env(self):
        return f"OPENAI_API_KEY={fake_key('sk-proj-', 64)}\nPORT=3000\n"

    def test_env_tracked(self):
        self.hit("PAH-W013", {".env": self.secret_env()}, "high",
                 git={"tracked": {".env"}, "untracked": set(), "history": {".env"}})

    def test_env_ignored(self):
        self.clean("PAH-W013", {".env": self.secret_env(), ".gitignore": ".env\n"},
                   git={"tracked": {".gitignore"}, "untracked": set(), "history": set()})

    def test_env_deleted_but_in_history(self):
        self.hit("PAH-W013", {".gitignore": ".env\n"}, "high",
                 git={"tracked": {".gitignore"}, "untracked": set(), "history": {".env"}})

    def test_env_not_ignored_outside_git(self):
        self.hit("PAH-W013", {".env": self.secret_env()})

    def test_env_ignored_outside_git(self):
        self.clean("PAH-W013", {".env": self.secret_env(), ".gitignore": "node_modules\n.env*\n!.env.example\n"})

    def test_env_example_with_placeholders(self):
        self.clean("PAH-W013", {".env.example": "OPENAI_API_KEY=your-key-here\nDATABASE_URL=postgres://user:password@localhost:5432/app\n"})

    def test_key_in_server_code(self):
        self.hit("PAH-W013", {"lib/openai.ts": f'export const openai = new OpenAI({{ apiKey: "{fake_key("sk-proj-", 64)}" }});\n'},
                 "high")

    def test_key_from_environment(self):
        self.clean("PAH-W013", {"lib/openai.ts": "export const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n"})

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_real_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                   "-C", str(root)]
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".env").write_text(self.secret_env(), encoding="utf-8")
            subprocess.run(git + ["add", ".env"], check=True)
            subprocess.run(git + ["commit", "-q", "-m", "init"], check=True)
            subprocess.run(git + ["rm", "-q", "--cached", ".env"], check=True)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            subprocess.run(git + ["add", ".gitignore"], check=True)
            subprocess.run(git + ["commit", "-q", "-m", "ignore env"], check=True)
            rep = appsec.check(root)
            hits = [f for f in rep.findings if f.rule == "PAH-W013"]
            self.assertTrue(any(f.severity == "high" and "history" in f.message for f in hits), hits)


class UploadTest(Case):  # 14. Upload a non-photo
    def test_multer_keeps_original_name(self):
        self.hit("PAH-W014", {"server.js": """
            const storage = multer.diskStorage({
              destination: "public/uploads",
              filename: (req, file, cb) => cb(null, file.originalname),
            });
            const upload = multer({ storage });
            app.post("/avatar", upload.single("avatar"), (req, res) => res.json({ url: "/uploads/" + req.file.filename }));
        """}, "high")

    def test_multer_checked(self):
        self.clean("PAH-W014", {"server.js": """
            const storage = multer.diskStorage({
              destination: "uploads",
              filename: (req, file, cb) => cb(null, crypto.randomUUID()),
            });
            const upload = multer({
              storage,
              limits: { fileSize: 2_000_000 },
              fileFilter: (req, file, cb) => cb(null, ["image/png", "image/jpeg"].includes(file.mimetype)),
            });
            app.post("/avatar", upload.single("avatar"), (req, res) => res.json({ ok: true }));
        """})

    def test_route_handler_writes_client_name(self):
        self.hit("PAH-W014", {"app/api/upload/route.ts": """
            import { writeFile } from "fs/promises";
            import path from "path";
            export async function POST(req: Request) {
              const form = await req.formData();
              const file = form.get("file") as File;
              await writeFile(path.join(process.cwd(), "public/uploads", file.name), Buffer.from(await file.arrayBuffer()));
              return Response.json({ ok: true });
            }
        """}, "high")

    def test_route_handler_checks_type(self):
        self.clean("PAH-W014", {"app/api/upload/route.ts": """
            import { writeFile } from "fs/promises";
            import path from "path";
            const ALLOWED = ["image/png", "image/jpeg", "image/webp"];
            export async function POST(req: Request) {
              const form = await req.formData();
              const file = form.get("file") as File;
              if (!ALLOWED.includes(file.type) || file.size > 2_000_000) return new Response("bad file", { status: 400 });
              const bytes = Buffer.from(await file.arrayBuffer());
              const kind = await fileTypeFromBuffer(bytes);
              if (!kind || !ALLOWED.includes(kind.mime)) return new Response("bad file", { status: 400 });
              await writeFile(path.join(process.cwd(), "uploads", `${crypto.randomUUID()}.${kind.ext}`), bytes);
              return Response.json({ ok: true });
            }
        """})

    def test_flask_saves_client_name(self):
        self.hit("PAH-W014", {"app.py": """
            @app.post("/photo")
            def photo():
                f = request.files["photo"]
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], f.filename))
                return "ok"
        """}, "high")

    def test_flask_secure_name_and_type(self):
        self.clean("PAH-W014", {"app.py": """
            ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

            @app.post("/photo")
            def photo():
                f = request.files["photo"]
                if not allowed_file(f.filename):
                    abort(400)
                Image.open(f.stream).verify()
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(f.filename)))
                return "ok"
        """})

    def test_svg_allowed(self):
        self.hit("PAH-W014", {"app/api/upload/route.ts": """
            const ALLOWED = ["image/png", "image/svg+xml"];
            export async function POST(req: Request) {
              const form = await req.formData();
              const file = form.get("file") as File;
              if (!ALLOWED.includes(file.type)) return new Response("bad file", { status: 400 });
              await put(`avatars/${crypto.randomUUID()}`, file, { access: "public" });
              return Response.json({ ok: true });
            }
        """})


def demo_jwt(role: str, iss: str = "supabase-demo") -> str:
    return f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}.{b64url({'iss': iss, 'role': role, 'exp': 1983812996})}." \
           f"{fake_key('', 43, seed=5)}"


class RealAppFalseAlarmTest(Case):
    """Shapes from twelve public apps (eight well-built, four deliberately vulnerable) that the first version flagged
    wrongly. Each input is written for the test, not copied from those apps."""

    def test_empty_example_values_are_not_secrets(self):
        self.clean("PAH-W013", {".env.local.example": "OPENAI_API_KEY=\nANTHROPIC_API_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n\n"
                                                      "# Get these from the Stripe dashboard\nSTRIPE_SECRET_KEY=\n"})

    def test_supabase_local_demo_keys(self):
        self.clean("PAH-W013", {
            "supabase/migrations/0001_storage.sql": f"declare service_role_key text := '{demo_jwt('service_role')}';\n",
            ".env.local.example": f'NEXT_PUBLIC_SUPABASE_ANON_KEY="{demo_jwt("anon")}"\n'})
        self.clean("PAH-W004", {".env.local.example": f'NEXT_PUBLIC_SUPABASE_ANON_KEY="{demo_jwt("anon")}"\n'})

    def test_real_service_role_key_still_found(self):
        self.hit("PAH-W013", {"supabase/seed.sql": f"select '{service_role_jwt()}';\n"}, "high")

    def test_words_inside_strings_are_not_the_body(self):
        self.clean("PAH-W006", {"app/api/chat/route.ts": """
            export async function POST(request: Request) {
              const json = await request.json();
              const answer = await ask(json.messages);
              return new Response(answer, { headers: { "Content-Type": "application/json" } });
            }
        """})

    def test_access_helper_counts_as_owner_check(self):
        self.clean("PAH-W002", {"app/api/posts/[postId]/route.ts": """
            export async function DELETE(req: Request, context) {
              const { params } = schema.parse(context);
              if (!(await verifyCurrentUserHasAccessToPost(params.postId))) return new Response(null, { status: 403 });
              await db.post.delete({ where: { id: params.postId } });
              return new Response(null, { status: 204 });
            }
        """})

    def test_superuser_dependency_counts(self):
        self.clean("PAH-W002", {"app/api/routes/users.py": """
            @router.patch("/{user_id}", dependencies=[Depends(get_current_active_superuser)])
            def update_user(*, session: SessionDep, user_id: uuid.UUID, user_in: UserUpdate):
                db_user = session.get(User, user_id)
                session.delete(db_user)
                return db_user
        """})

    def test_capitalised_owner_key(self):
        self.clean("PAH-W002", {"routes/payment.ts": """
            export function getCard () {
              return async (req, res) => {
                const card = await CardModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
                res.json(card);
              };
            }
        """})

    def test_instance_update_is_not_a_lookup(self):
        self.clean("PAH-W002", {"routes/avatar.ts": """
            export function uploadAvatar () {
              return async (req, res) => {
                const user = await UserModel.findByPk(res.locals.userId);
                const ext = detect(req.file.buffer);
                await user.update({ avatar: `/uploads/${user.id}.${ext}` });
                res.sendStatus(204);
              };
            }
        """})

    def test_session_id_is_not_from_the_request(self):
        self.clean("PAH-W002", {"app/routes/contributions.js": """
            this.handleUpdate = (req, res, next) => {
              const { preTax, roth } = req.body;
              const userId = req.session.userId;
              contributionsDAO.update(userId, preTax, roth, (err, saved) => res.render("contributions", saved));
            };
        """})

    def test_constant_script(self):
        self.clean("PAH-W001", {"app/layout.tsx": """
            const THEME_SCRIPT = `(function () { document.documentElement.dataset.theme = "dark"; })();`;
            export default function Layout({ children }) {
              return <html><head><script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} /></head>{children}</html>;
            }
        """})

    def test_react_rendered_markup(self):
        self.clean("PAH-W001", {"lib/editor.tsx": """
            export function toDoc(content: string) {
              const markup = renderToString(<Markdown>{content}</Markdown>);
              const box = document.createElement("div");
              box.innerHTML = markup;
              return parse(box);
            }
        """})

    def test_ternary_of_literals(self):
        self.clean("PAH-W001", {"templates/base.html": "<script>toggle.innerHTML = dark ? 'moon' : 'sun';</script>\n"})

    def test_django_form_field(self):
        self.clean("PAH-W001", {"templates/login.html": "{{ form.username|safe }}\n"})

    def test_page_host_is_not_attacker_input(self):
        got = found({"config/dev.js": "module.exports = { snippet: () => document.write(\"<script src='//\" + "
                                      "location.host + \"/reload.js'></\" + \"script>\") };\n"}, at_least="high")
        self.assertNotIn("PAH-W001", got)

    def test_ejs_include(self):
        self.clean("PAH-W001", {"views/layout.ejs": "<main><%- include(partial) %></main>\n"})

    def test_multer_sanitised_name(self):
        self.clean("PAH-W014", {"server.js": """
            const upload = multer({
              storage: multer.diskStorage({
                destination: (req, file, cb) => cb(TYPES[file.mimetype] ? null : new Error("type"), "uploads"),
                filename: (req, file, cb) => cb(null, sanitizeFilename(file.originalname).toLowerCase()),
              }),
            });
        """})

    def test_config_schema_quantity(self):
        # a stock level in the app's own configuration is not something a customer sends
        self.clean("PAH-W010", {"lib/config.schema.ts": "export const Product = z.object({ name: z.string(), "
                                                         "quantity: z.number().optional() });\n"})

    def test_rate_limit_on_another_path(self):
        self.hit("PAH-W011", {
            "server.js": 'app.use("/rest/user/reset-password", rateLimit({ windowMs: 300000, max: 100 }));\n',
            "routes/verify.js": """
                router.post("/verify-code", async (req, res) => {
                  const row = await Codes.findOne({ where: { email: req.body.email } });
                  if (!row || row.code !== req.body.code) return res.status(401).end();
                  res.json(await login(row.email));
                });
            """}, "high")


class RealAppMissTest(Case):
    """Holes the deliberately vulnerable apps have that the first version missed. Inputs written for the test."""

    def test_handler_returned_by_a_factory(self):
        self.hit("PAH-W002", {"routes/basket.ts": """
            export function retrieveBasket () {
              return (req, res, next) => {
                const id = req.params.id;
                BasketModel.findOne({ where: { id } }).then((basket) => res.json(basket)).catch(next);
              };
            }
        """})

    def test_dao_lookup_by_user_id_from_url(self):
        self.hit("PAH-W002", {"app/routes/allocations.js": """
            this.displayAllocations = (req, res, next) => {
              const userId = req.params.userId;
              allocationsDAO.getByUserId(userId, (err, docs) => res.render("allocations", docs));
            };
        """})

    def test_template_engine_escaping_off(self):
        self.hit("PAH-W001", {"server.js": 'swig.setDefaults({ autoescape: false });\n'})
        self.hit("PAH-W001", {"app.js": 'nunjucks.configure("views", { autoescape: false, express: app });\n'})

    def test_upper_bound_is_not_a_lower_bound(self):
        self.hit("PAH-W010", {"routes/basketItems.ts": """
            export function addItem () {
              return async (req, res) => {
                const product = await ProductModel.findByPk(req.body.ProductId);
                if (product.stock >= req.body.quantity) {
                  await BasketItemModel.create({ ProductId: product.id, quantity: req.body.quantity });
                  return res.sendStatus(201);
                }
                res.status(400).json({ error: "not enough stock" });
              };
            }
        """})

    def test_mongo_where_with_input(self):
        self.hit("PAH-W012", {"app/data/allocations-dao.js": """
            this.getByUserIdAndThreshold = (userId, threshold, callback) => {
              allocations.find({ $where: `this.userId == ${userId} && this.stocks > '${threshold}'` }).toArray(callback);
            };
        """}, "high")

    def test_mongo_operator_injection_in_login(self):
        self.hit("PAH-W012", {"routes/auth.js": """
            const mongoose = require("mongoose");
            router.post("/login", async (req, res) => {
              const user = await User.findOne({ email: req.body.email, password: req.body.password });
              if (!user) return res.status(401).end();
              res.json({ token: sign(user) });
            });
        """}, "high")

    def test_mongo_cast_values_are_fine(self):
        self.clean("PAH-W012", {"routes/auth.js": """
            const mongoose = require("mongoose");
            router.post("/login", async (req, res) => {
              const user = await User.findOne({ email: String(req.body.email) });
              if (!user || !(await bcrypt.compare(String(req.body.password), user.hash))) return res.status(401).end();
              res.json({ token: sign(user) });
            });
        """})

    def test_comment_before_the_selector(self):
        self.hit("PAH-W002", {"routes/reviews.ts": """
            export function updateReview () {
              return (req, res, next) => {
                db.reviewsCollection.update( // the review to change
                  { _id: req.body.id }, // chosen by the client
                  { $set: { message: req.body.message } }
                ).then((result) => res.json(result), next);
              };
            }
        """})

    def test_sequelize_where_is_not_a_mongo_query(self):
        self.clean("PAH-W012", {"routes/order.ts": """
            import * as db from "../data/mongodb";
            export function placeOrder () {
              return (req, res, next) => {
                const id = req.params.id;
                BasketModel.findOne({ where: { id }, include: [{ model: ProductModel }] }).then((b) => res.json(b));
              };
            }
        """})

    def test_sequelize_find_by_body_id(self):
        self.hit("PAH-W002", {"core/appHandler.js": """
            module.exports.userEditSubmit = function (req, res) {
              db.User.find({ where: { id: req.body.id } }).then((user) => {
                user.update({ email: req.body.email, name: req.body.name }).then(() => res.redirect("/app/useredit"));
              });
            };
        """})


class GeneralTest(Case):
    def test_every_rule_has_metadata(self):
        for n in range(1, 15):
            rid = f"PAH-W{n:03d}"
            self.assertIn(rid, appsec.RULE_IDS)
            meta = appsec.RULES[rid]
            self.assertTrue(meta.title and meta.why and meta.fix and meta.refs, rid)

    def test_skips_dependencies_and_build_output(self):
        got = found({"node_modules/lib/index.js": "el.innerHTML = data.html;\n",
                     ".next/server/page.js": "el.innerHTML = data.html;\n",
                     "dist/app.js": "el.innerHTML = data.html;\n"}, at_least="low")
        self.assertEqual(got, {})

    def test_evidence_never_carries_a_key(self):
        key = fake_key("sk-proj-", 64, seed=11)
        rep = run({"lib/ai.ts": f'export const ai = new OpenAI({{ dangerouslyAllowBrowser: true, apiKey: "{key}" }});\n'})
        self.assertEqual({f.rule for f in rep.findings}, {"PAH-W004", "PAH-W013"})
        for f in rep.findings:
            self.assertNotIn(key[8:30], f.evidence + f.message, f)

    def test_skips_built_bundles(self):
        got = found({"static/js/index.k-9rUdPI.js": "el.innerHTML = data.html;\n",
                     "public/app.min.js": "el.innerHTML = data.html;\n",
                     "public/vendor.js": "var a=1;" * 600 + "\nel.innerHTML = data.html;\n"}, at_least="low")
        self.assertEqual(got, {})

    def test_upload_type_named_but_never_stored(self):
        # framework code that only names UploadFile stores nothing
        self.clean("PAH-W014", {"app/deps.py": "from fastapi import UploadFile\n\ndef size(f: UploadFile) -> int:\n"
                                               "    return f.size\n"})

    def test_svg_mentioned_outside_an_allowlist(self):
        self.clean("PAH-W014", {"app/api/upload/route.ts": """
            const ALLOWED = ["image/png", "image/jpeg"];
            export async function POST(req: Request) {
              const form = await req.formData();
              const file = form.get("file") as File;
              if (!ALLOWED.includes(file.type)) return new Response("no svg or other types", { status: 400 });
              const icon = "logo.svg";
              await put(`avatars/${crypto.randomUUID()}`, file, { access: "public" });
              return Response.json({ ok: true, icon });
            }
        """})

    def test_test_files_are_low_at_most(self):
        rep = run({"tests/test_db.py": "def find(cur, name):\n    cur.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"})
        self.assertTrue(rep.findings)
        self.assertTrue(all(rank(f.severity) <= rank("low") for f in rep.findings), rep.findings)

    def test_verdict_and_stats(self):
        rep = run({"server.js": 'app.use("/admin", adminRouter);\n'})
        self.assertEqual(rep.verdict, "block")
        self.assertEqual(rep.stats["files"], 1)
        self.assertEqual(run({"README.md": "hello\n"}).verdict, "pass")


class WrittenFileTest(unittest.TestCase):
    """The note an agent gets right after it writes a file with one of the holes."""

    def test_note_for_sql_injection(self):
        note = appsec.note_for_write("lib/users.js", "export const f = (e) => pool.query(`SELECT * FROM users WHERE email = '${e}'`);\n")
        self.assertIn("PAH-W012", note)
        self.assertIn("lib/users.js:1", note)

    def test_no_note_for_clean_file(self):
        self.assertEqual(appsec.note_for_write("lib/users.js", 'export const f = (e) => pool.query("SELECT 1 WHERE a = $1", [e]);\n'), "")

    def test_no_note_for_context_dependent_rules(self):
        # an admin route's guard may live in another file: only the whole-app check can say
        self.assertEqual(appsec.note_for_write("server.js", 'app.get("/admin/users", async (req, res) => res.json(await User.find()));\n'), "")

    def test_no_note_for_test_files(self):
        self.assertEqual(appsec.note_for_write("tests/users.test.js", "pool.query(`SELECT * FROM u WHERE e = '${e}'`);\n"), "")

    def post_hook(self, project: Path, rel: str, content: str):
        from pah import hooks

        target = project / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        event = {"hook_event_name": "PostToolUse", "tool_name": "Write", "cwd": str(project), "session_id": "t",
                 "tool_input": {"file_path": str(target), "content": content},
                 "tool_response": {"filePath": str(target), "success": True}}
        old = os.environ.pop("PAH_NO_APP_HINTS", None)
        try:
            out, code = hooks.run("post", json.dumps(event))
        finally:
            if old is not None:
                os.environ["PAH_NO_APP_HINTS"] = old
        self.assertEqual(code, 0)
        return json.loads(out)["hookSpecificOutput"]["additionalContext"] if out else ""

    def test_claude_code_post_hook_tells_the_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.post_hook(Path(tmp), "users.js",
                                 "export const f = (e) => pool.query(`SELECT * FROM users WHERE email = '${e}'`);\n")
        self.assertIn("PAH-W012", ctx)
        self.assertIn("users.js:1", ctx)

    def test_project_inside_a_folder_named_like_tests(self):
        # only the path inside the project says whether a file is a test: ~/examples/shop is an app
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "examples" / "e2e" / "shop"
            ctx = self.post_hook(project, "app/api/users/route.ts",
                                 "export async function GET(req) {\n"
                                 "  return Response.json(await pool.query(`SELECT * FROM users WHERE id = ${req.url}`));\n"
                                 "}\n")
            self.assertIn("app/api/users/route.ts:2", ctx)
            self.assertEqual(self.post_hook(project, "tests/users.test.ts",
                                            "pool.query(`SELECT * FROM u WHERE e = '${e}'`);\n"), "")


class CliTest(unittest.TestCase):
    def test_appsec_command(self):
        from pah import cli

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "server.js").write_text('app.use("/admin", adminRouter);\n', encoding="utf-8")
            out = Path(tmp, "report.json")
            code = cli.main(["appsec", tmp, "--json", "-o", str(out)])
            data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(data["verdict"], "block")
        self.assertEqual(data["findings"][0]["rule"], "PAH-W003")

    def test_mcp_tool(self):
        from pah import mcp_server

        self.assertIn("check_app", {t["name"] for t in mcp_server.TOOLS})
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "server.js").write_text('app.use("/admin", adminRouter);\n', encoding="utf-8")
            text, is_error = mcp_server.call_tool("check_app", {"path": tmp})
        self.assertFalse(is_error)
        self.assertIn("PAH-W003", text)


if __name__ == "__main__":
    unittest.main()
