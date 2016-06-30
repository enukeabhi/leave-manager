using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Leave.Utils;
using Leave.Models;
using System.Data;
using System.Data.SqlClient;
using Dapper;
using DapperExtensions;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using BitFactory.Logging;
using System.Threading.Tasks;

namespace Leave.Controllers
{

    [Authorize(Roles = "Admin, HR,Employee")]
    public class EmployeeController : Controller
    {
        private string _connectionString = string.Empty;


        #region Contructor
        public EmployeeController()
            : this(new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext())), new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new ApplicationDbContext())))
        {
            // Initialize connection string
            _connectionString = LeaveDB.ConnectionString;
        }

        public EmployeeController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            UserManager = userManager;
            RoleManager = roleManager;
            UserManager.UserValidator = new UserValidator<ApplicationUser>(UserManager) { AllowOnlyAlphanumericUserNames = false };
        }

        #endregion

        public UserManager<ApplicationUser> UserManager { get; private set; }
        public RoleManager<IdentityRole> RoleManager { get; private set; }


        #region Actions : Index
        //
        // GET: /AddEmployee/
        public ActionResult Index()
        {
            ListDataService.RefreshLists();
            return View();
        }
        [HttpPost]
        public ActionResult Index(EmployeeVM employeeVM)
        {
            try
            {
                using (IDbConnection cn = new SqlConnection(_connectionString))
                {
                    cn.Open();
                    employeeVM.Employee.DateTimeStampRecord(DbChangeType.Create);
                    cn.Insert<Employee>(employeeVM.Employee);
                    if (employeeVM.Employee.EmpId > 0)
                    {
                        LeaveStatus leaveStatus = new LeaveStatus();
                        leaveStatus.EmpId = employeeVM.Employee.EmpId;
                        cn.Insert<LeaveStatus>(leaveStatus);
                        var user = new ApplicationUser() { UserName = employeeVM.Employee.Email, FirstName = employeeVM.Employee.EmpFirstName, LastName = employeeVM.Employee.EmpLastName, Email = employeeVM.Employee.Email };
                        var result = UserManager.Create(user, employeeVM.Password.Trim());
                        if (result.Succeeded)
                        {
                            string defaultRole = UserRole.Employee.ToString();
                            if (employeeVM.Employee.IsSupervisor)
                            {
                                defaultRole = UserRole.Supervisor.ToString();
                            }
                            UserManager.AddToRole(user.Id, defaultRole);
                            var curUser = UserManager.FindByName(User.Identity.Name);
                            var task = new Task(() => { MailUtility.SendAccountMail(employeeVM.Employee.EmpFirstName, employeeVM.Password.Trim(), employeeVM.Employee.Email, curUser.Email, curUser.FirstName); });
                            task.Start();
                            //MailUtility.SendAccountMail(employeeVM.Employee.EmpFirstName, employeeVM.Password, employeeVM.Employee.Email, curUser.Email, curUser.FirstName);
                        }
                    }
                    cn.Close();
                }
            }
            catch (Exception ex)
            {
                ConfigLogger.Instance.LogError(ex);
            }
            return RedirectToAction("Index");
        }

        #endregion

        public ActionResult CreatePopupEmployee(int empId = 0)
        {
            EmployeeVM employeeVM = new EmployeeVM();
            if (empId > 0)
            {
                using (IDbConnection cn = new SqlConnection(_connectionString))
                {
                    Employee employee = new Employee();
                    int[] supIds;
                    cn.Open();
                    employee = cn.Get<Employee>(empId);
                    supIds = cn.GetList<EmpSupervisor>().Where(x => x.EmpId == empId).Select(x => x.SupId).ToArray();
                    cn.Close();
                    employeeVM.Employee = employee;
                    employeeVM.SupIds = supIds;
                }
                return PartialView("_EditEmployee", employeeVM);
            }
            return PartialView("_EditEmployee");

        }
        #region Action : DeleteEmployee
        public ActionResult DeleteEmployee(int empId = 0)
        {
            if (empId > 0)
            {
                try
                {
                    using (IDbConnection cn = new SqlConnection(_connectionString))
                    {
                        cn.Open();
                        Employee employee = cn.Get<Employee>(empId);
                        if (employee != null)
                        {
                            employee.DateTimeStampRecord(DbChangeType.Update);
                            employee.IsActive = false;
                            cn.Update<Employee>(employee);
                        }
                        cn.Close();
                    }
                    return Json("Deleted successfully.", JsonRequestBehavior.AllowGet);
                }
                catch (Exception ex)
                {
                    ConfigLogger.Instance.LogError(ex);
                }
            }
            return Json("Some error occurred.", JsonRequestBehavior.AllowGet);
        }
        #endregion

        #region Action : UpdateEmployeeData
        [HttpPost]
        public JsonResult UpdateEmployeeData(EmployeeVM employeeVM, FormCollection frm)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(employeeVM.Employee.EmpCode))
                {
                    if (IsExistEmpCode(employeeVM.Employee.EmpCode, employeeVM.Employee.EmpId))
                    {
                        return Json("Employee Code already exist!", JsonRequestBehavior.AllowGet);
                    }
                }
                using (IDbConnection cn = new SqlConnection(_connectionString))
                {
                    cn.Open();
                    if (employeeVM.Employee.EmpId > 0)
                    {
                        employeeVM.Employee.DateTimeStampRecord(DbChangeType.Update);
                        employeeVM.Employee.IsActive = true;
                        cn.Update<Employee>(employeeVM.Employee);
                        SaveEmpSupIds(cn, employeeVM.Employee.EmpId, employeeVM.SupIds);
                        string userName = cn.GetList<AspNetUsers>().Where(x => x.Email == employeeVM.Employee.Email).FirstOrDefault().UserName;
                        var user = UserManager.FindByName(userName);
                        string role = UserManager.GetRoles(user.Id)[0];
                        string defaultRole = UserRole.Employee.ToString();
                        if (employeeVM.Employee.IsSupervisor)
                        {
                            defaultRole = UserRole.Supervisor.ToString();
                        }
                        UserManager.RemoveFromRole(user.Id, role);
                        UserManager.AddToRole(user.Id, defaultRole);
                        user.FirstName = employeeVM.Employee.EmpFirstName;
                        user.LastName = employeeVM.Employee.EmpLastName;
                        UserManager.Update(user);
                    }
                    else
                    {
                        employeeVM.Employee.DateTimeStampRecord(DbChangeType.Create);
                        employeeVM.Employee.IsActive = true;
                        cn.Insert<Employee>(employeeVM.Employee);
                        if (employeeVM.Employee.EmpId > 0)
                        {
                            SaveEmpSupIds(cn, employeeVM.Employee.EmpId, employeeVM.SupIds);
                            LeaveStatus leaveStatus = new LeaveStatus();
                            leaveStatus.EmpId = employeeVM.Employee.EmpId;
                            cn.Insert<LeaveStatus>(leaveStatus);
                            var user = new ApplicationUser() { UserName = employeeVM.Employee.Email, FirstName = employeeVM.Employee.EmpFirstName, LastName = employeeVM.Employee.EmpLastName, Email = employeeVM.Employee.Email };
                            var result = UserManager.Create(user, employeeVM.Password.Trim());
                            if (result.Succeeded)
                            {
                                string defaultRole = UserRole.Employee.ToString();
                                if (employeeVM.Employee.IsSupervisor)
                                {
                                    defaultRole = UserRole.Supervisor.ToString();
                                }
                                UserManager.AddToRole(user.Id, defaultRole);
                                var curUser = UserManager.FindByName(User.Identity.Name);
                                var task = new Task(() => { MailUtility.SendAccountMail(employeeVM.Employee.EmpFirstName, employeeVM.Password.Trim(), employeeVM.Employee.Email, curUser.Email, curUser.FirstName); });
                                task.Start();
                                //MailUtility.SendAccountMail(employeeVM.Employee.EmpFirstName, employeeVM.Password, employeeVM.Employee.Email, curUser.Email, curUser.FirstName);
                            }
                            else
                            {
                                cn.Delete<Employee>(employeeVM.Employee);
                                return Json("Email already exist!", JsonRequestBehavior.AllowGet);
                            }
                        }
                    }
                    cn.Close();

                }
                ListDataService.RefreshLists();
            }
            catch (Exception ex)
            {
                ConfigLogger.Instance.LogError(ex);
                return Json("Some error occurred.", JsonRequestBehavior.AllowGet);
            }
            return Json("Success", JsonRequestBehavior.AllowGet);
        }

        #endregion


        private void SaveEmpSupIds(IDbConnection cn, int EmpId, int[] supIds)
        {
            try
            {
                if (EmpId > 0 && supIds != null)
                {
                    var predicate = Predicates.Field<EmpSupervisor>(x => x.EmpId, Operator.Eq, EmpId);
                    cn.Delete<EmpSupervisor>(predicate);
                    foreach (int supId in supIds)
                    {
                        EmpSupervisor empSupervisor = new EmpSupervisor() { EmpId = EmpId, SupId = supId };
                        cn.Insert<EmpSupervisor>(empSupervisor);
                    }
                }
            }
            catch (Exception ex)
            {
                ConfigLogger.Instance.LogError(ex);
            }
        }

        private bool IsExistEmpCode(string empCode, int empId)
        {
            bool IsExist = false;
            using (IDbConnection cn = new SqlConnection(_connectionString))
            {
                cn.Open();
                IsExist = cn.GetList<Employee>().Where(x => x.EmpCode.Trim().ToLower() == empCode.Trim().ToLower() && x.EmpId != empId).Count() > 0;
                cn.Close();
            }
            return IsExist;
        }
    }
}