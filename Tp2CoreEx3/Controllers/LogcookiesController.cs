using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Tp2CoreEx3.Model;

namespace Tp2CoreEx3.Controllers
{
    public class LogcookiesController : Controller
    {
        // GET: Logcookies
        public ActionResult Index()
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri("https://localhost:44330");
            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            HttpResponseMessage response = client.GetAsync("api/login/default").Result;
            User x = response.Content.ReadAsAsync<User>().Result;
            if (x == null)
            {
                return RedirectToAction("Login");
            }
            return View();

        }

        // GET: Logcookies/Create
        public ActionResult Login()
        {
            return View();
        }

        // POST: Logcookies/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(User user)
        {
            try
            {
                HttpClient client = new HttpClient();
                client.BaseAddress = new Uri("https://localhost:44330");
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                var message = client.PostAsJsonAsync("api/login", user).Result;
                CookieOptions option = new CookieOptions();
                option.HttpOnly = true;
                Response.Cookies.Append("JwtToken2",message.ToString(),option);

                return RedirectToAction();
            }
            catch
            {
                return View();
            }
        }
    }
}