using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using identity.Data;
using identity.Models;
using identity.Services;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
             // Database Connection Parameters
            String connectionString = buildConnectionString();
            
            // WRITE CONNECTION STRING TO THE CONSOLE
            Console.WriteLine("********************************************************************************");
            Console.WriteLine("[Startup] Connection String: " + connectionString);
            Console.WriteLine("********************************************************************************");

            // NOW THAT WE HAVE OUR CONNECTION STRING, WE CAN ESTABLISH OUR DB CONTEXT
            services.AddDbContext<ApplicationDbContext>
            (
                options => options.UseMySQL(connectionString)
            );

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = false;
                options.Password.RequiredUniqueChars = 6;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 10;
                options.Lockout.AllowedForNewUsers = true;

                // User settings
                options.User.RequireUniqueEmail = true;
            });

            services.ConfigureApplicationCookie(options =>
            {
                // Cookie settings
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                // If the LoginPath isn't set, ASP.NET Core defaults 
                // the path to /Account/Login.
                options.LoginPath = "/Account/Login";
                // If the AccessDeniedPath isn't set, ASP.NET Core defaults 
                // the path to /Account/AccessDenied.
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.SlidingExpiration = true;
            });            

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private String buildConnectionString()
        {
            Console.WriteLine("[Startup.buildConnectionString()] : BEGIN");

            String connectionString = null;
            try
            {
                connectionString = Environment.GetEnvironmentVariable("LOCAL_CONNECTION_STRING");
                if (connectionString == null)
                {
                    string vcapServices = System.Environment.GetEnvironmentVariable("VCAP_SERVICES");
                    if (vcapServices != null)
                    {
                        dynamic json = JsonConvert.DeserializeObject(vcapServices);
                        foreach (dynamic obj in json.Children())
                        {
                            dynamic credentials = (((JProperty)obj).Value[0] as dynamic).credentials;
                            if (credentials != null)
                            {
                                string host     = credentials.host;
                                string username = credentials.username;
                                string password = credentials.password;
                                string port     = credentials.port;
                                string db_name  = credentials.db_name;

                                connectionString = "Username=" + username + ";"
                                    + "Password=" + password + ";"
                                    + "Host=" + host + ";"
                                    + "Port=" + port + ";"
                                    + "Database=" + db_name + ";Pooling=true;";
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception in [Startup.buildConnectionString()]:");
                Console.WriteLine(e);
            }
            Console.WriteLine("[Startup.buildConnectionString()] : END");
            return connectionString;
        }

    }
}
