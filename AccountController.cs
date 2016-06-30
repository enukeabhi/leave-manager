using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Leave.Models;
using System.Data;
using System.Data.SqlClient;
using Leave.Utils;
using Dapper;
using DapperExtensions;
using BitFactory.Logging;
namespace Leave.Controllers
{

    

    [Authorize]
    public class AccountController : Controller
    {
        private string _connectionString = string.Empty;

         public AccountController()
            : this(new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext())), new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new ApplicationDbContext())))
        {
            // Initialize connection string
            _connectionString = LeaveDB.ConnectionString;
        }

        public AccountController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            UserManager = userManager;
            RoleManager = roleManager;
            UserManager.UserValidator = new UserValidator<ApplicationUser>(UserManager) { AllowOnlyAlphanumericUserNames = false };
        }

        public UserManager<ApplicationUser> UserManager { get; private set; }
        public RoleManager<IdentityRole> RoleManager { get; private set; }



        #region Actions : Login 
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }
        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.UserName, model.Password);
                if (user != null)
                {
                    await SignInAsync(user, model.RememberMe);
                    //CheckSession();
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        
        #endregion


        #region Actions : Legal
        [Authorize(Roles = "Admin,HR,Employee, Supervisor")]
        public ActionResult Legal()
        {
            return View();
        }
        
        #endregion


        #region Actions : Register
        // GET: /Account/Register
        //[AllowAnonymous]
        [Authorize(Roles = "Admin, HR")]
        public ActionResult Register()
        {


            return View();

        }

        // POST: /Account/Register
        [Authorize(Roles = "Admin, HR")]
        [HttpPost]
        //[AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser() { UserName = model.UserName, FirstName = model.FirstName, LastName = model.LastName, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    string defaultRole = UserRole.HR.ToString();
                    if (model.IsAdmin)
                    {
                        defaultRole = UserRole.Admin.ToString();
                    }
                    UserManager.AddToRole(user.Id, defaultRole);
                    var curUser = UserManager.FindByName(User.Identity.Name);
                    var task = new Task(() => { MailUtility.SendAdminHRAccountMail(model.FirstName, model.UserName, model.Password, model.Email, curUser.Email, curUser.FirstName); });
                    task.Start();
                    ListDataService.RefreshLists();
                    //await SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    AddErrors(result);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        
        #endregion


        #region Actions : Manage
        // GET: /Account/Manage
        public ActionResult Manage(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.Error ? "An error has occurred."
                : "";
            ViewBag.HasLocalPassword = HasPassword();
            ViewBag.ReturnUrl = Url.Action("Manage");
            return View();
        }

        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Manage(ManageUserViewModel model)
        {
            bool hasPassword = HasPassword();
            ViewBag.HasLocalPassword = hasPassword;
            ViewBag.ReturnUrl = Url.Action("Manage");
            if (hasPassword)
            {
                if (ModelState.IsValid)
                {
                    IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
            }
            else
            {
                // User does not have a password so remove any validation errors caused by a missing OldPassword field
                ModelState state = ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        
        #endregion


        #region Actions : Detail
        [Authorize(Roles = "Employee, Supervisor")]
        [HttpGet]
        public ActionResult Detail()
        {
            EmployeeVM employeeVM = new EmployeeVM();
            var curUser = UserManager.FindByName(User.Identity.Name);
            using (IDbConnection cn = new SqlConnection(_connectionString))
            {
                cn.Open();
                employeeVM.Employee = cn.GetList<Employee>().Where(x => x.Email == curUser.Email).FirstOrDefault();
                employeeVM.SupIds = cn.GetList<EmpSupervisor>().Where(x => x.EmpId == employeeVM.Employee.EmpId).Select(x => x.SupId).ToArray();
                cn.Close();
            }
            return View(employeeVM);
        } 
        #endregion


        #region Actions : ChangePassword
        [Authorize(Roles = "Admin, HR,Employee")]
        [HttpGet]
        public ActionResult ChangePassword()
        {
            IEnumerable<ApplicationUser> userList = new List<ApplicationUser>();
            try
            {
                var context = new ApplicationDbContext();
                //userList = context.Users.Where(x => !x.Roles.Select(y => y.Role.Name).Contains("Admin")).ToList().OrderBy(x=>x.UserName);
                userList = context.Users.ToList().OrderBy(x => x.UserName);
            }
            catch (Exception ex)
            {
                ConfigLogger.Instance.LogError(ex);
            }
            return View(userList);
        }
        
        [Authorize(Roles = "Admin, HR,Employee")]
        [HttpPost]
        public JsonResult ChangePassword(string userId, string password)
        {
            try
            {
                var curUser = UserManager.FindByName(User.Identity.Name);
                var user = UserManager.FindById(userId);
                UserManager.RemovePassword(userId);
                UserManager.AddPassword(userId, password);
                //var task = new Task(() => { MailUtility.SendChangePasswordMail(user.FirstName + " " + user.LastName, password, user.UserName, user.Email, curUser.Email, curUser.FirstName + " " + curUser.LastName); });
                //task.Start();
            }
            catch (Exception ex)
            {
                ConfigLogger.Instance.LogError(ex);
                return Json("Error");
            }
            return Json("Success");
        }
        #endregion


        #region Actions : Logoff
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Login", "Account");
        } 
        #endregion


        protected override void Dispose(bool disposing)
        {
            if (disposing && UserManager != null)
            {
                UserManager.Dispose();
                UserManager = null;
            }
            base.Dispose(disposing);
        }







        #region Actions : Disassociate
        // POST: /Account/Disassociate
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Disassociate(string loginProvider, string providerKey)
        {
            ManageMessageId? message = null;
            IdentityResult result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("Manage", new { Message = message });
        }

        #endregion

        #region External Login Actions
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var user = await UserManager.FindAsync(loginInfo.Login);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
                return RedirectToLocal(returnUrl);
            }
            else
            {
                // If the user does not have an account, then prompt the user to create an account
                ViewBag.ReturnUrl = returnUrl;
                ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { UserName = loginInfo.DefaultUserName });
            }
        }

        //
        // POST: /Account/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new ChallengeResult(provider, Url.Action("LinkLoginCallback", "Account"), User.Identity.GetUserId());
        }

        //
        // GET: /Account/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
            }
            var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
            if (result.Succeeded)
            {
                return RedirectToAction("Manage");
            }
            return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser() { UserName = model.UserName };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInAsync(user, isPersistent: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }


        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        [ChildActionOnly]
        public ActionResult RemoveAccountList()
        {
            var linkedAccounts = UserManager.GetLogins(User.Identity.GetUserId());
            ViewBag.ShowRemoveButton = HasPassword() || linkedAccounts.Count > 1;
            return (ActionResult)PartialView("_RemoveAccountPartial", linkedAccounts);
        }
        
        #endregion
        
        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private bool HasPassword()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            Error
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        private class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion

        //[Authorize(Roles="Employee, Supervisor")]
        //[HttpGet]
        //public ActionResult Edit()
        //{
        //    EmployeeVM employeeVM = new EmployeeVM();
        //    var curUser = UserManager.FindByName(User.Identity.Name);
        //    using (IDbConnection cn = new SqlConnection(_connectionString))
        //    {
        //        cn.Open();
        //        employeeVM.Employee = cn.GetList<Employee>().Where(x => x.Email == curUser.Email).FirstOrDefault();
        //        cn.Close();
        //    }
        //    return View(employeeVM);
        //}

        //[HttpPost]
        //public ActionResult Edit(EmployeeVM employeeVM)
        //{
        //    using (IDbConnection cn = new SqlConnection(_connectionString))
        //    {
        //        cn.Open();
        //        employeeVM.Employee.DateTimeStampRecord(DbChangeType.Update);
        //        cn.Update<Employee>(employeeVM.Employee);
        //        string userName = cn.GetList<AspNetUsers>().Where(x => x.Email == employeeVM.Employee.Email).FirstOrDefault().UserName;
        //        var user = UserManager.FindByName(userName);    
        //        user.FirstName = employeeVM.Employee.EmpFirstName;
        //        user.LastName = employeeVM.Employee.EmpLastName;
        //        UserManager.Update(user);
        //        cn.Close();
        //    }
        //    return RedirectToAction("Index", "Home");
        //}


    }
}