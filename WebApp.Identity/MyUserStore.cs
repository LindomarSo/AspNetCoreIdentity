﻿using Dapper;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WebApp.Identity
{
    public class MyUserStore : IUserStore<MyUser>, IUserPasswordStore<MyUser>
    {
        public async Task<IdentityResult> CreateAsync(MyUser user, CancellationToken cancellationToken)
        {
            using (var connection = GetOpenConnetction())
            {
                await connection.ExecuteAsync(
                    "INSERT INTO Users (Id, UserName, NormalizedUserName, " +
                                    "PasswordHash) VALUES(@id,@userName,@normalizedUserName,@passwordHash)",
                   new
                   {
                       id = user.Id,
                       userName = user.UserName,
                       normalizedUserName = user.NormalizedUserName,
                       passwordHash = user.PasswordHash
                   });
            }

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(MyUser user, CancellationToken cancellationToken)
        {
            using (var connection = GetOpenConnetction())
            {
                await connection.ExecuteAsync(
                    "DELETE FROM Users WHERE Id=@id",
                   new
                   {
                       id = user.Id
                   });
            }

            return IdentityResult.Success;
        } 

        public void Dispose()
        {
            
        }

        public static DbConnection GetOpenConnetction() 
        {
            var connection = new SqlConnection(@"Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=IdentityCurso;Data Source=DESKTOP-FEE42EV\SQLEXPRESS");

            connection.Open();

            return connection;
        }

        public async Task<MyUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            using(var connection = GetOpenConnetction())
            {
                return await connection.QueryFirstOrDefaultAsync<MyUser>(
                    "SELECT * FROM Users Where Id=@id", new { id = userId });
            }
        }

        public async Task<MyUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            using(var connection = GetOpenConnetction())
            {
                return await connection.QueryFirstOrDefaultAsync<MyUser>(
                    "SELECT * FROM Users WHERE NormalizedUserName=@userName",
                    new { userName = normalizedUserName });
            }
        }

        public Task<string> GetNormalizedUserNameAsync(MyUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetUserIdAsync(MyUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(MyUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task SetNormalizedUserNameAsync(MyUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(MyUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(MyUser user, CancellationToken cancellationToken)
        {
            using(var connection = GetOpenConnetction())
            {
                await connection.ExecuteAsync(
                    "UPDATE Users SET UserName=@userName, NormalizedUserName=@normalizedUserName, " +
                                    "PasswordHash=@passwordHash WHERE Id=@id",
                   new
                   {
                       id = user.Id,
                       userName = user.UserName,
                       normalizedUserName = user.NormalizedUserName,
                       passwordHash = user.PasswordHash
                   });
            }

            return IdentityResult.Success;
        }

        public Task SetPasswordHashAsync(MyUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(MyUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(MyUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null);
        }
    }
}