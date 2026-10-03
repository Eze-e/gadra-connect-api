using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = builder.Configuration["Jwt:Key"]
    ?? "dev-only-key-change-me-before-deploying-32chars";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddDbContext<AppDb>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=gadra.db"));

builder.Services.AddAuthentication("Bearer").AddJwtBearer("Bearer", o =>
{
    o.MapInboundClaims = false;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        IssuerSigningKey = signingKey,
        NameClaimType = "email",
        RoleClaimType = "role"
    };
});
builder.Services.AddAuthorization();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();
    var adminEmail = builder.Configuration["Admin:Email"] ?? "admin@gadra.local";
    var adminPassword = builder.Configuration["Admin:Password"]
        ?? (app.Environment.IsDevelopment() ? "Admin123!" : null);
    if (adminPassword is not null && !db.Users.Any(u => u.Role == "admin"))
    {
        db.Users.Add(new UserEntity
        {
            FullName = "Admin", Email = adminEmail, Role = "admin", Status = "active",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(adminPassword)
        });
        db.SaveChanges();
    }
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// ---------- helpers ----------
IResult Deny(string message, int code = 403) => Results.Json(new { message }, statusCode: code);

string Token(UserEntity u)
{
    var claims = new[]
    {
        new Claim("sub", u.Id.ToString()),
        new Claim("email", u.Email),
        new Claim("role", u.Role)
    };
    var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddHours(12),
        signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256));
    return new JwtSecurityTokenHandler().WriteToken(token);
}

object UserDto(UserEntity u) => new
{
    id = u.Id.ToString(), fullName = u.FullName, email = u.Email, role = u.Role, status = u.Status
};

DateTime? ParseDate(string? s) =>
    DateTime.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

int? AgeOf(string? dob)
{
    var d = ParseDate(dob);
    var today = DateTime.UtcNow.Date;
    if (d is null || d > today) return null;
    var age = today.Year - d.Value.Year;
    if (d.Value.Date > today.AddYears(-age)) age--;
    return age;
}

void Notify(AppDb db, string email, string message) =>
    db.Notifications.Add(new NotificationEntity
    {
        Id = Guid.NewGuid().ToString(), RecipientEmail = email, Message = message, CreatedAt = DateTime.UtcNow
    });

async Task<UserEntity?> Me(HttpContext ctx, AppDb db)
{
    var email = ctx.User.FindFirst("email")?.Value;
    return email is null ? null : await db.Users.FirstOrDefaultAsync(u => u.Email == email);
}

// Checks role and that the account is cleared (consent / background check) for actions.
async Task<(UserEntity? U, IResult? Err)> Need(HttpContext ctx, AppDb db, string role)
{
    var u = await Me(ctx, db);
    if (u is null) return (null, Results.Unauthorized());
    if (u.Role != role) return (null, Deny($"This action is for {role}s only."));
    if (u.Status == "pending_consent") return (null, Deny("Guardian consent is still pending."));
    if (u.Status == "pending_background_check") return (null, Deny("Your background check is still pending."));
    return (u, null);
}

async Task<List<object>> RequestDtos(AppDb db, IQueryable<RequestEntity> query, string? viewerTutorEmail)
{
    var list = await query.OrderByDescending(r => r.CreatedAt).ToListAsync();
    var ids = list.Select(r => r.Id).ToList();
    var interests = await db.Interests.Where(i => ids.Contains(i.RequestId)).ToListAsync();
    return list.Select(r => (object)new
    {
        id = r.Id,
        learnerName = r.LearnerName,
        // Tutors only see a learner's email once matched with them.
        learnerEmail = viewerTutorEmail is not null && r.MatchedTutorEmail != viewerTutorEmail ? "" : r.LearnerEmail,
        subject = r.Subject, grade = r.Grade, availability = r.Availability, goals = r.Goals,
        status = r.Status,
        interestedTutors = interests.Where(i => i.RequestId == r.Id).Select(i => i.TutorEmail).ToList(),
        matchedTutorEmail = r.MatchedTutorEmail
    }).ToList();
}

object SessionDto(SessionEntity s) => new
{
    id = s.Id, requestId = s.RequestId, subject = s.Subject,
    learnerEmail = s.LearnerEmail, learnerName = s.LearnerName,
    tutorEmail = s.TutorEmail, tutorName = s.TutorName,
    date = s.Date, durationMins = s.DurationMins, notes = s.Notes,
    feedback = s.FeedbackRating is null ? null : new { rating = s.FeedbackRating, comment = s.FeedbackComment ?? "" }
};

// ---------- health ----------
app.MapGet("/api/health", () => Results.Ok(new { ok = true }));

// ---------- auth ----------
var auth = app.MapGroup("/api/auth");

auth.MapPost("/register/learner", async (LearnerReg r, AppDb db) =>
{
    var email = (r.Email ?? "").Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(r.FullName) || !email.Contains('@') || (r.Password ?? "").Length < 6)
        return Deny("Please enter a name, a valid email and a password of at least 6 characters.", 400);
    if (await db.Users.AnyAsync(u => u.Email == email))
        return Deny("An account with this email already exists.", 409);

    var age = AgeOf(r.DateOfBirth);
    if (age is null) return Deny("Date of birth must be a valid past date (YYYY-MM-DD).", 400);
    var minor = age < 18;
    if (minor && (string.IsNullOrWhiteSpace(r.GuardianName) || string.IsNullOrWhiteSpace(r.GuardianEmail) || !r.GuardianConsent))
        return Deny("Guardian details and consent are required for learners under 18.", 400);

    db.Users.Add(new UserEntity
    {
        FullName = r.FullName.Trim(), Email = email, Role = "learner",
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(r.Password!),
        Status = minor ? "pending_consent" : "active",
        DateOfBirth = r.DateOfBirth, Grade = r.Grade, Subjects = string.Join(",", r.Subjects ?? Array.Empty<string>()),
        GuardianName = minor ? r.GuardianName : null, GuardianEmail = minor ? r.GuardianEmail : null
    });
    await db.SaveChangesAsync();
    return Results.Ok(new { status = minor ? "pending_consent" : "active" });
});

auth.MapPost("/register/tutor", async (TutorReg r, AppDb db) =>
{
    var email = (r.Email ?? "").Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(r.FullName) || !email.Contains('@') || (r.Password ?? "").Length < 6)
        return Deny("Please enter a name, a valid email and a password of at least 6 characters.", 400);
    if (await db.Users.AnyAsync(u => u.Email == email))
        return Deny("An account with this email already exists.", 409);

    db.Users.Add(new UserEntity
    {
        FullName = r.FullName.Trim(), Email = email, Role = "tutor",
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(r.Password!),
        Status = "pending_background_check",
        Subjects = string.Join(",", r.Subjects ?? Array.Empty<string>()),
        Grades = r.Grades, Availability = r.Availability, Bio = r.Bio
    });
    await db.SaveChangesAsync();
    return Results.Ok(new { status = "pending_background_check" });
});

auth.MapPost("/login", async (LoginReq r, AppDb db) =>
{
    var email = (r.Email ?? "").Trim().ToLowerInvariant();
    var u = await db.Users.FirstOrDefaultAsync(x => x.Email == email && x.Role == r.Role);
    if (u is null || !BCrypt.Net.BCrypt.Verify(r.Password ?? "", u.PasswordHash))
        return Deny("Incorrect email or password.", 401);
    return Results.Ok(new { token = Token(u), user = UserDto(u) });
});

// ---------- requests ----------
var requests = app.MapGroup("/api/requests").RequireAuthorization();

requests.MapGet("/mine", async (HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null || me.Role != "learner") return Deny("This is for learners only.");
    return Results.Ok(await RequestDtos(db, db.Requests.Where(r => r.LearnerEmail == me.Email), null));
});

requests.MapGet("/open", async (HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null || me.Role != "tutor") return Deny("This is for tutors only.");
    if (me.Status != "active") return Results.Ok(new List<object>());
    var email = me.Email;
    return Results.Ok(await RequestDtos(db,
        db.Requests.Where(r => r.Status == "open" || r.MatchedTutorEmail == email), email));
});

requests.MapPost("/", async (NewRequest b, HttpContext ctx, AppDb db) =>
{
    var (me, err) = await Need(ctx, db, "learner");
    if (err is not null) return err;
    if (string.IsNullOrWhiteSpace(b.Subject) || string.IsNullOrWhiteSpace(b.Grade) ||
        string.IsNullOrWhiteSpace(b.Availability) || string.IsNullOrWhiteSpace(b.Goals))
        return Deny("Subject, grade, availability and goals are required.", 400);

    var entity = new RequestEntity
    {
        Id = Guid.NewGuid().ToString(), LearnerEmail = me!.Email, LearnerName = me.FullName,
        Subject = b.Subject.Trim(), Grade = b.Grade.Trim(), Availability = b.Availability.Trim(),
        Goals = b.Goals.Trim(), Status = "open", CreatedAt = DateTime.UtcNow
    };
    db.Requests.Add(entity);
    await db.SaveChangesAsync();
    var dto = await RequestDtos(db, db.Requests.Where(r => r.Id == entity.Id), null);
    return Results.Ok(dto.First());
});

requests.MapPost("/{id}/interest", async (string id, HttpContext ctx, AppDb db) =>
{
    var (me, err) = await Need(ctx, db, "tutor");
    if (err is not null) return err;
    var r = await db.Requests.FindAsync(id);
    if (r is null) return Deny("Request not found.", 404);
    if (r.Status != "open") return Deny("This request is no longer open.", 409);
    if (!await db.Interests.AnyAsync(i => i.RequestId == id && i.TutorEmail == me!.Email))
    {
        db.Interests.Add(new InterestEntity { RequestId = id, TutorEmail = me!.Email });
        Notify(db, r.LearnerEmail, $"A tutor is interested in your {r.Subject} request. Awaiting admin approval.");
        await db.SaveChangesAsync();
    }
    return Results.NoContent();
});

// ---------- sessions ----------
var sessions = app.MapGroup("/api/sessions").RequireAuthorization();

sessions.MapGet("/mine", async (HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null) return Results.Unauthorized();
    var list = await db.Sessions
        .Where(s => s.LearnerEmail == me.Email || s.TutorEmail == me.Email)
        .OrderByDescending(s => s.CreatedAt).ToListAsync();
    return Results.Ok(list.Select(SessionDto).ToList());
});

sessions.MapPost("/", async (NewSession b, HttpContext ctx, AppDb db) =>
{
    var (me, err) = await Need(ctx, db, "tutor");
    if (err is not null) return err;
    var r = await db.Requests.FindAsync(b.RequestId);
    if (r is null || r.MatchedTutorEmail != me!.Email)
        return Deny("You can only log sessions for learners you are matched with.");
    var date = ParseDate(b.Date);
    if (date is null || date > DateTime.UtcNow.Date.AddDays(1))
        return Deny("Date must be a valid date (YYYY-MM-DD), not in the future.", 400);
    if (b.DurationMins < 15 || b.DurationMins > 240)
        return Deny("Duration must be between 15 and 240 minutes.", 400);
    if (string.IsNullOrWhiteSpace(b.Notes)) return Deny("Please add a note on what was covered.", 400);

    var s = new SessionEntity
    {
        Id = Guid.NewGuid().ToString(), RequestId = r.Id, Subject = r.Subject,
        LearnerEmail = r.LearnerEmail, LearnerName = r.LearnerName,
        TutorEmail = me.Email, TutorName = me.FullName,
        Date = b.Date!.Trim(), DurationMins = b.DurationMins, Notes = b.Notes.Trim(),
        CreatedAt = DateTime.UtcNow
    };
    db.Sessions.Add(s);
    Notify(db, r.LearnerEmail, $"{me.FullName} logged a {r.Subject} session on {s.Date}. Please leave feedback.");
    await db.SaveChangesAsync();
    return Results.Ok(SessionDto(s));
});

sessions.MapPost("/{id}/feedback", async (string id, FeedbackReq b, HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null || me.Role != "learner") return Deny("Only the learner can leave feedback.");
    var s = await db.Sessions.FindAsync(id);
    if (s is null || s.LearnerEmail != me.Email) return Deny("Session not found.", 404);
    if (s.FeedbackRating is not null) return Deny("Feedback was already submitted.", 409);
    if (b.Rating < 1 || b.Rating > 5) return Deny("Rating must be between 1 and 5.", 400);
    s.FeedbackRating = b.Rating;
    s.FeedbackComment = b.Comment?.Trim();
    Notify(db, s.TutorEmail, $"{s.LearnerName} left {b.Rating}/5 feedback for your {s.Subject} session.");
    await db.SaveChangesAsync();
    return Results.NoContent();
});

// ---------- notifications ----------
var notifications = app.MapGroup("/api/notifications").RequireAuthorization();

notifications.MapGet("/", async (HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null) return Results.Unauthorized();
    var list = await db.Notifications.Where(n => n.RecipientEmail == me.Email)
        .OrderByDescending(n => n.CreatedAt).ToListAsync();
    return Results.Ok(list.Select(n => new
    {
        id = n.Id, recipientEmail = n.RecipientEmail, message = n.Message,
        createdAt = n.CreatedAt.ToString("o"), read = n.Read
    }).ToList());
});

notifications.MapPost("/read", async (HttpContext ctx, AppDb db) =>
{
    var me = await Me(ctx, db);
    if (me is null) return Results.Unauthorized();
    var unread = await db.Notifications.Where(n => n.RecipientEmail == me.Email && !n.Read).ToListAsync();
    foreach (var n in unread) n.Read = true;
    await db.SaveChangesAsync();
    return Results.NoContent();
});

// ---------- admin (for the web portal) ----------
var admin = app.MapGroup("/api/admin").RequireAuthorization(p => p.RequireRole("admin"));

admin.MapGet("/pending", async (AppDb db) =>
{
    var users = await db.Users.Where(u => u.Status != "active")
        .Select(u => new { u.Email, u.FullName, u.Role, u.Status }).ToListAsync();
    var withInterest = await db.Interests.Select(i => i.RequestId).Distinct().ToListAsync();
    var reqs = await RequestDtos(db, db.Requests.Where(r => r.Status == "open" && withInterest.Contains(r.Id)), null);
    return Results.Ok(new { users, requests = reqs });
});

admin.MapPost("/users/{email}/confirm-consent", async (string email, AppDb db) =>
{
    var u = await db.Users.FirstOrDefaultAsync(x => x.Email == email.ToLowerInvariant() && x.Role == "learner");
    if (u is null) return Deny("Learner not found.", 404);
    u.Status = "active";
    Notify(db, u.Email, "Guardian consent was confirmed. You can now submit tutoring requests.");
    await db.SaveChangesAsync();
    return Results.NoContent();
});

admin.MapPost("/users/{email}/clear-background-check", async (string email, AppDb db) =>
{
    var u = await db.Users.FirstOrDefaultAsync(x => x.Email == email.ToLowerInvariant() && x.Role == "tutor");
    if (u is null) return Deny("Tutor not found.", 404);
    u.Status = "active";
    Notify(db, u.Email, "Your background check was cleared. You can now browse learner requests.");
    await db.SaveChangesAsync();
    return Results.NoContent();
});

admin.MapPost("/requests/{id}/approve", async (string id, ApproveReq b, AppDb db) =>
{
    var r = await db.Requests.FindAsync(id);
    if (r is null) return Deny("Request not found.", 404);
    if (r.Status != "open") return Deny("This request is already matched.", 409);
    var tutorEmail = (b.TutorEmail ?? "").ToLowerInvariant();
    if (!await db.Interests.AnyAsync(i => i.RequestId == id && i.TutorEmail == tutorEmail))
        return Deny("That tutor has not shown interest in this request.", 400);
    var tutor = await db.Users.FirstOrDefaultAsync(u => u.Email == tutorEmail && u.Role == "tutor" && u.Status == "active");
    if (tutor is null) return Deny("That tutor is not cleared to be matched.", 400);

    r.Status = "matched";
    r.MatchedTutorEmail = tutorEmail;
    Notify(db, r.LearnerEmail, $"Your {r.Subject} request has been matched with a tutor.");
    Notify(db, tutorEmail, $"You have been matched with {r.LearnerName} for {r.Subject}.");
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

// ---------- request bodies ----------
record LearnerReg(string? FullName, string? Email, string? Password, string? DateOfBirth, string? Grade,
    string[]? Subjects, string? GuardianName, string? GuardianEmail, bool GuardianConsent);
record TutorReg(string? FullName, string? Email, string? Password, string[]? Subjects,
    string? Grades, string? Availability, string? Bio);
record LoginReq(string? Email, string? Password, string? Role);
record NewRequest(string? Subject, string? Grade, string? Availability, string? Goals);
record NewSession(string? RequestId, string? Date, int DurationMins, string? Notes);
record FeedbackReq(int Rating, string? Comment);
record ApproveReq(string? TutorEmail);

// ---------- database ----------
class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<RequestEntity> Requests => Set<RequestEntity>();
    public DbSet<InterestEntity> Interests => Set<InterestEntity>();
    public DbSet<SessionEntity> Sessions => Set<SessionEntity>();
    public DbSet<NotificationEntity> Notifications => Set<NotificationEntity>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<UserEntity>().HasIndex(u => u.Email).IsUnique();
        b.Entity<InterestEntity>().HasIndex(i => new { i.RequestId, i.TutorEmail }).IsUnique();
    }
}

class UserEntity
{
    public int Id { get; set; }
    public string FullName { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "";
    public string Status { get; set; } = "active";
    public string? DateOfBirth { get; set; }
    public string? Grade { get; set; }
    public string? Subjects { get; set; }
    public string? GuardianName { get; set; }
    public string? GuardianEmail { get; set; }
    public string? Grades { get; set; }
    public string? Availability { get; set; }
    public string? Bio { get; set; }
}

class RequestEntity
{
    public string Id { get; set; } = "";
    public string LearnerEmail { get; set; } = "";
    public string LearnerName { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Grade { get; set; } = "";
    public string Availability { get; set; } = "";
    public string Goals { get; set; } = "";
    public string Status { get; set; } = "open";
    public string? MatchedTutorEmail { get; set; }
    public DateTime CreatedAt { get; set; }
}

class InterestEntity
{
    public int Id { get; set; }
    public string RequestId { get; set; } = "";
    public string TutorEmail { get; set; } = "";
}

class SessionEntity
{
    public string Id { get; set; } = "";
    public string RequestId { get; set; } = "";
    public string Subject { get; set; } = "";
    public string LearnerEmail { get; set; } = "";
    public string LearnerName { get; set; } = "";
    public string TutorEmail { get; set; } = "";
    public string TutorName { get; set; } = "";
    public string Date { get; set; } = "";
    public int DurationMins { get; set; }
    public string Notes { get; set; } = "";
    public int? FeedbackRating { get; set; }
    public string? FeedbackComment { get; set; }
    public DateTime CreatedAt { get; set; }
}

class NotificationEntity
{
    public string Id { get; set; } = "";
    public string RecipientEmail { get; set; } = "";
    public string Message { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public bool Read { get; set; }
}