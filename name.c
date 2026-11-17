/* Cyber Incident Response Tracker - single-file version.
   Build: gcc -std=c99 -o incident_tracker incident_tracker_single.c */

/* ===== incident.h ===== */
#ifndef INCIDENT_H
#define INCIDENT_H

#include <stddef.h>
#include <time.h>

#define TYPE_LEN 32
#define NAME_LEN 32

typedef enum { SEV_LOW = 1, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL } Severity;
typedef enum { ST_OPEN = 0, ST_IN_PROGRESS, ST_ESCALATED, ST_CLOSED } Status;

typedef struct {
    int      id;
    char     type[TYPE_LEN];
    Severity severity;
    char     assigned_to[NAME_LEN];
    Status   status;
    time_t   created_at;
    int      was_escalated;   /* 1 if it was ever escalated (kept after closing) */
} Incident;

/* Dynamic list: heap array that grows with realloc. */
typedef struct {
    Incident *items;
    size_t    count;
    size_t    capacity;
    int       next_id;
} IncidentList;

const char *severity_name(Severity s);
const char *status_name(Status s);

int       list_init(IncidentList *list);
void      list_free(IncidentList *list);
int       list_push(IncidentList *list, const Incident *inc);
Incident *list_add(IncidentList *list, const char *type, Severity sev,
                   const char *assignee, time_t created_at);
Incident *list_find(IncidentList *list, int id);

/* Returns 0 ok, -1 not found, -2 invalid transition. */
int       list_set_status(IncidentList *list, int id, Status new_status);

void      incident_print_header(void);
void      incident_print_row(const Incident *inc, time_t now);
void      list_print_all(const IncidentList *list, time_t now);

#endif

/* ===== log.h ===== */
#ifndef LOG_H
#define LOG_H

#define MAX_LOG 100
#define LOG_LEN 160

/* Append a formatted message to the in-memory event log (circular array). */
void log_event(const char *fmt, ...);

/* Print the stored events, oldest first. */
void log_print(void);

#endif

/* ===== escalation.h ===== */
#ifndef ESCALATION_H
#define ESCALATION_H

#include <time.h>
#define ESCALATION_THRESHOLD_HOURS 48.0

double      incident_age_hours(const Incident *inc, time_t now);
int         is_unresolved(const Incident *inc);
int         needs_escalation(const Incident *inc, time_t now);
const char *escalation_target(Severity sev);
void        escalate_incident(Incident *inc);

/* Scan the whole list; returns how many incidents were escalated. */
int         run_escalation_scan(IncidentList *list, time_t now);

#endif

/* ===== report.h ===== */
#ifndef REPORT_H
#define REPORT_H

#include <time.h>
void generate_report(const IncidentList *list, time_t now);

#endif

/* ===== storage.h ===== */
#ifndef STORAGE_H
#define STORAGE_H

/* Return number of incidents saved/loaded, or -1 on error. */
int save_incidents(const IncidentList *list, const char *filename);
int load_incidents(IncidentList *list, const char *filename);

#endif

/* ===== log.c ===== */
#include <stdio.h>
#include <stdarg.h>
/* Array-based audit log: a fixed 2D array used as a circular buffer. */
static char event_log[MAX_LOG][LOG_LEN];
static int total_events = 0;

void log_event(const char *fmt, ...)
{
    va_list args;
    int slot = total_events % MAX_LOG;

    va_start(args, fmt);
    vsnprintf(event_log[slot], LOG_LEN, fmt, args);
    va_end(args);
    total_events++;
}

void log_print(void)
{
    int shown = (total_events < MAX_LOG) ? total_events : MAX_LOG;
    int first = total_events - shown;
    int i;

    printf("\n===== EVENT LOG (%d entries) =====\n", shown);
    if (shown == 0) {
        printf("  (no events yet)\n");
        return;
    }
    for (i = 0; i < shown; i++)
        printf("  %3d. %s\n", first + i + 1, event_log[(first + i) % MAX_LOG]);
}

/* ===== incident.c ===== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define INITIAL_CAPACITY 4

const char *severity_name(Severity s)
{
    switch (s) {
    case SEV_LOW:      return "Low";
    case SEV_MEDIUM:   return "Medium";
    case SEV_HIGH:     return "High";
    case SEV_CRITICAL: return "Critical";
    }
    return "Unknown";
}

const char *status_name(Status s)
{
    switch (s) {
    case ST_OPEN:        return "Open";
    case ST_IN_PROGRESS: return "In Progress";
    case ST_ESCALATED:   return "Escalated";
    case ST_CLOSED:      return "Closed";
    }
    return "Unknown";
}

int list_init(IncidentList *list)
{
    list->items = malloc(INITIAL_CAPACITY * sizeof(Incident));
    if (list->items == NULL)
        return -1;
    list->count = 0;
    list->capacity = INITIAL_CAPACITY;
    list->next_id = 1;
    return 0;
}

void list_free(IncidentList *list)
{
    free(list->items);
    list->items = NULL;
    list->count = list->capacity = 0;
}

int list_push(IncidentList *list, const Incident *inc)
{
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity * 2;
        Incident *bigger = realloc(list->items, new_cap * sizeof(Incident));
        if (bigger == NULL)
            return -1;              /* old block is still valid */
        list->items = bigger;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *inc;
    if (inc->id >= list->next_id)
        list->next_id = inc->id + 1;
    return 0;
}

Incident *list_add(IncidentList *list, const char *type, Severity sev,
                   const char *assignee, time_t created_at)
{
    Incident inc;

    memset(&inc, 0, sizeof inc);
    inc.id = list->next_id;
    snprintf(inc.type, TYPE_LEN, "%s", type);
    inc.severity = sev;
    snprintf(inc.assigned_to, NAME_LEN, "%s", assignee);
    inc.status = ST_OPEN;
    inc.created_at = created_at;
    inc.was_escalated = 0;

    if (list_push(list, &inc) != 0)
        return NULL;
    log_event("Incident #%d (%s, %s) created, assigned to %s",
              inc.id, inc.type, severity_name(sev), inc.assigned_to);
    return &list->items[list->count - 1];
}

Incident *list_find(IncidentList *list, int id)
{
    Incident *p;
    Incident *end = list->items + list->count;

    for (p = list->items; p < end; p++)      /* pointer traversal */
        if (p->id == id)
            return p;
    return NULL;
}

int list_set_status(IncidentList *list, int id, Status new_status)
{
    Incident *inc = list_find(list, id);
    int ok = 0;

    if (inc == NULL)
        return -1;

    switch (inc->status) {
    case ST_OPEN:        ok = (new_status == ST_IN_PROGRESS || new_status == ST_CLOSED); break;
    case ST_IN_PROGRESS: ok = (new_status == ST_CLOSED); break;
    case ST_ESCALATED:   ok = (new_status == ST_CLOSED); break;
    case ST_CLOSED:      ok = 0; break;
    }
    if (!ok)
        return -2;

    log_event("Incident #%d status: %s -> %s", id,
              status_name(inc->status), status_name(new_status));
    inc->status = new_status;
    return 0;
}

void incident_print_header(void)
{
    printf("%-4s %-15s %-9s %-18s %-12s %8s\n",
           "ID", "Type", "Severity", "Assigned To", "Status", "Age(h)");
    printf("---- --------------- --------- ------------------ ------------ --------\n");
}

void incident_print_row(const Incident *inc, time_t now)
{
    printf("%-4d %-15s %-9s %-18s %-12s %8.1f\n",
           inc->id, inc->type, severity_name(inc->severity),
           inc->assigned_to, status_name(inc->status),
           incident_age_hours(inc, now));
}

void list_print_all(const IncidentList *list, time_t now)
{
    size_t i;

    if (list->count == 0) {
        printf("\nNo incidents recorded.\n");
        return;
    }
    printf("\n");
    incident_print_header();
    for (i = 0; i < list->count; i++)
        incident_print_row(&list->items[i], now);
}

/* ===== escalation.c ===== */
#include <stdio.h>
#include <string.h>
/*
 * Escalation flow (CO1):
 *   for each incident in the list:
 *       1. skip if already Closed or Escalated        (status check)
 *       2. compute age = now - created_at (hours)
 *       3. if age > 48 hours                          (age check)
 *             pick a target by severity               (severity check)
 *             reassign, mark Escalated, write log
 */

double incident_age_hours(const Incident *inc, time_t now)
{
    return difftime(now, inc->created_at) / 3600.0;
}

int is_unresolved(const Incident *inc)
{
    return inc->status == ST_OPEN || inc->status == ST_IN_PROGRESS;
}

int needs_escalation(const Incident *inc, time_t now)
{
    return is_unresolved(inc) &&
           incident_age_hours(inc, now) > ESCALATION_THRESHOLD_HOURS;
}

const char *escalation_target(Severity sev)
{
    if (sev >= SEV_CRITICAL) return "CISO";
    if (sev == SEV_HIGH)     return "SOC Lead";
    return "Tier-2 Analyst";
}

void escalate_incident(Incident *inc)
{
    char previous[NAME_LEN];
    const char *target = escalation_target(inc->severity);

    snprintf(previous, NAME_LEN, "%s", inc->assigned_to);
    snprintf(inc->assigned_to, NAME_LEN, "%s", target);
    inc->status = ST_ESCALATED;
    inc->was_escalated = 1;

    log_event("Incident #%d ESCALATED: %s -> %s", inc->id, previous, target);
}

int run_escalation_scan(IncidentList *list, time_t now)
{
    Incident *p;
    Incident *end = list->items + list->count;
    int escalated = 0;

    for (p = list->items; p < end; p++) {
        if (needs_escalation(p, now)) {
            double age = incident_age_hours(p, now);
            escalate_incident(p);
            printf("  [ESCALATED] #%d %s (%s) open for %.1f h -> now with %s\n",
                   p->id, p->type, severity_name(p->severity), age, p->assigned_to);
            escalated++;
        }
    }
    return escalated;
}

/* ===== report.c ===== */
#include <stdio.h>
static int pred_open(const Incident *i)      { return i->status == ST_OPEN || i->status == ST_IN_PROGRESS; }
static int pred_escalated(const Incident *i) { return i->status == ST_ESCALATED; }
static int pred_closed(const Incident *i)    { return i->status == ST_CLOSED; }

/* Prints every incident matching the predicate (function pointer). */
static void print_section(const IncidentList *list, time_t now,
                          const char *title, int (*pred)(const Incident *))
{
    size_t i;
    int found = 0;

    printf("\n-- %s --\n", title);
    for (i = 0; i < list->count; i++) {
        if (pred(&list->items[i])) {
            if (!found) {
                incident_print_header();
                found = 1;
            }
            incident_print_row(&list->items[i], now);
        }
    }
    if (!found)
        printf("  (none)\n");
}

void generate_report(const IncidentList *list, time_t now)
{
    int open_n = 0, progress_n = 0, escalated_n = 0, closed_n = 0, closed_after_esc = 0;
    int by_sev[5] = {0};              /* index 1..4 = severity */
    char stamp[64];
    struct tm *tm_now = localtime(&now);
    size_t i;

    for (i = 0; i < list->count; i++) {
        const Incident *inc = &list->items[i];
        by_sev[inc->severity]++;
        switch (inc->status) {
        case ST_OPEN:        open_n++; break;
        case ST_IN_PROGRESS: progress_n++; break;
        case ST_ESCALATED:   escalated_n++; break;
        case ST_CLOSED:      closed_n++; if (inc->was_escalated) closed_after_esc++; break;
        }
    }

    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M", tm_now);
    printf("\n==========================================\n");
    printf("      INCIDENT RESPONSE REPORT\n");
    printf("      Generated: %s\n", stamp);
    printf("==========================================\n");
    printf("Total incidents : %zu\n", list->count);
    printf("Open            : %d (new: %d, in progress: %d)\n",
           open_n + progress_n, open_n, progress_n);
    printf("Escalated       : %d\n", escalated_n);
    printf("Closed          : %d (%d were escalated before closing)\n",
           closed_n, closed_after_esc);
    printf("By severity     : Low %d | Medium %d | High %d | Critical %d\n",
           by_sev[SEV_LOW], by_sev[SEV_MEDIUM], by_sev[SEV_HIGH], by_sev[SEV_CRITICAL]);

    print_section(list, now, "OPEN INCIDENTS", pred_open);
    print_section(list, now, "ESCALATED INCIDENTS", pred_escalated);
    print_section(list, now, "CLOSED INCIDENTS", pred_closed);
}

/* ===== storage.c ===== */
#include <stdio.h>
int save_incidents(const IncidentList *list, const char *filename)
{
    FILE *fp = fopen(filename, "w");
    size_t i;

    if (fp == NULL)
        return -1;
    for (i = 0; i < list->count; i++) {
        const Incident *p = &list->items[i];
        fprintf(fp, "%d|%s|%d|%s|%d|%lld|%d\n", p->id, p->type, (int)p->severity,
                p->assigned_to, (int)p->status, (long long)p->created_at,
                p->was_escalated);
    }
    fclose(fp);
    return (int)list->count;
}

int load_incidents(IncidentList *list, const char *filename)
{
    FILE *fp = fopen(filename, "r");
    char line[256];
    int loaded = 0;

    if (fp == NULL)
        return -1;
    while (fgets(line, sizeof line, fp)) {
        Incident inc;
        int sev, st;
        long long created;

        if (sscanf(line, "%d|%31[^|]|%d|%31[^|]|%d|%lld|%d",
                   &inc.id, inc.type, &sev, inc.assigned_to, &st,
                   &created, &inc.was_escalated) == 7
            && sev >= SEV_LOW && sev <= SEV_CRITICAL
            && st >= ST_OPEN && st <= ST_CLOSED) {
            inc.severity = (Severity)sev;
            inc.status = (Status)st;
            inc.created_at = (time_t)created;
            if (list_push(list, &inc) == 0)
                loaded++;
        }
    }
    fclose(fp);
    return loaded;
}

/* ===== main.c ===== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define DATA_FILE "incidents.dat"

static const char *INCIDENT_TYPES[] = {
    "Malware", "Phishing", "Ransomware", "DDoS", "Data Breach", "Insider Threat"
};
#define NUM_TYPES (sizeof INCIDENT_TYPES / sizeof INCIDENT_TYPES[0])

/* Simulated clock: lets you "fast-forward" to demo the 48-hour rule. */
static long sim_offset_hours = 0;

static time_t current_time(void)
{
    return time(NULL) + (time_t)sim_offset_hours * 3600;
}

static void read_line(const char *prompt, char *buf, size_t n)
{
    char *p;

    printf("%s", prompt);
    if (!fgets(buf, (int)n, stdin)) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\n")] = '\0';
    for (p = buf; *p; p++)
        if (*p == '|')
            *p = '_';               /* '|' is the file separator */
}

static int read_int(const char *prompt, int min, int max)
{
    char buf[64];
    char *end;
    long v;

    for (;;) {
        printf("%s", prompt);
        if (!fgets(buf, sizeof buf, stdin))
            return min;             /* EOF: fall back to the lowest option */
        v = strtol(buf, &end, 10);
        if (end != buf && (*end == '\n' || *end == '\0') && v >= min && v <= max)
            return (int)v;
        printf("  Invalid input. Enter a number from %d to %d.\n", min, max);
    }
}

static void add_incident_flow(IncidentList *list)
{
    char assignee[NAME_LEN];
    char custom[TYPE_LEN];
    const char *type;
    int t, sev, hours_ago;
    size_t i;
    Incident *inc;

    printf("\nIncident types:\n");
    for (i = 0; i < NUM_TYPES; i++)
        printf("  %zu. %s\n", i + 1, INCIDENT_TYPES[i]);
    printf("  %zu. Other (type your own)\n", NUM_TYPES + 1);

    t = read_int("Choose type: ", 1, (int)NUM_TYPES + 1);
    if (t == (int)NUM_TYPES + 1) {
        read_line("Enter incident type: ", custom, sizeof custom);
        if (custom[0] == '\0')
            snprintf(custom, sizeof custom, "Other");
        type = custom;
    } else {
        type = INCIDENT_TYPES[t - 1];
    }

    sev = read_int("Severity (1=Low 2=Medium 3=High 4=Critical): ", 1, 4);
    read_line("Assigned to (analyst name): ", assignee, sizeof assignee);
    if (assignee[0] == '\0')
        snprintf(assignee, sizeof assignee, "Unassigned");
    hours_ago = read_int("Reported how many hours ago? (0 = just now): ", 0, 10000);

    inc = list_add(list, type, (Severity)sev, assignee,
                   current_time() - (time_t)hours_ago * 3600);
    if (inc == NULL) {
        printf("Error: out of memory, incident not saved.\n");
        return;
    }
    printf("Incident #%d recorded.\n", inc->id);
}

static void update_status_flow(IncidentList *list)
{
    int id, choice, rc;

    if (list->count == 0) {
        printf("\nNo incidents to update.\n");
        return;
    }
    id = read_int("Incident ID: ", 1, 1000000);
    choice = read_int("New status (1=In Progress, 2=Closed): ", 1, 2);
    rc = list_set_status(list, id, choice == 1 ? ST_IN_PROGRESS : ST_CLOSED);

    if (rc == 0)
        printf("Incident #%d updated.\n", id);
    else if (rc == -1)
        printf("No incident with ID %d.\n", id);
    else
        printf("That status change is not allowed from the current status.\n");
}

static void monitoring_flow(IncidentList *list)
{
    int cycles = read_int("Monitoring cycles (1-50): ", 1, 50);
    int step   = read_int("Hours that pass per cycle (1-72): ", 1, 72);
    int c, total = 0;

    printf("\nStarting monitoring...\n");
    for (c = 1; c <= cycles; c++) {
        int n;
        sim_offset_hours += step;
        printf("Cycle %d (+%d h, total simulated shift: %ld h)\n",
               c, step, sim_offset_hours);
        n = run_escalation_scan(list, current_time());
        if (n == 0)
            printf("  no escalations\n");
        total += n;
    }
    printf("Monitoring finished. %d incident(s) escalated.\n", total);
}

static void print_menu(void)
{
    printf("\n====== CYBER INCIDENT RESPONSE TRACKER ======\n");
    printf(" 1. Add incident\n");
    printf(" 2. View all incidents\n");
    printf(" 3. Update incident status\n");
    printf(" 4. Run escalation check now\n");
    printf(" 5. Run monitoring simulation\n");
    printf(" 6. Fast-forward time (hours)\n");
    printf(" 7. Generate report\n");
    printf(" 8. View event log\n");
    printf(" 9. Save to file\n");
    printf("10. Load from file\n");
    printf(" 0. Exit\n");
}

int main(void)
{
    IncidentList list;
    int choice, n;

    if (list_init(&list) != 0) {
        fprintf(stderr, "Fatal: could not allocate memory.\n");
        return EXIT_FAILURE;
    }

    n = load_incidents(&list, DATA_FILE);
    if (n > 0)
        printf("Loaded %d saved incident(s) from %s.\n", n, DATA_FILE);

    do {
        print_menu();
        choice = read_int("Choice: ", 0, 10);

        switch (choice) {
        case 1: add_incident_flow(&list); break;
        case 2: list_print_all(&list, current_time()); break;
        case 3: update_status_flow(&list); break;
        case 4:
            printf("\nRunning escalation check...\n");
            n = run_escalation_scan(&list, current_time());
            printf("%s\n", n ? "Done." : "No incidents need escalation.");
            break;
        case 5: monitoring_flow(&list); break;
        case 6:
            n = read_int("Hours to fast-forward (1-500): ", 1, 500);
            sim_offset_hours += n;
            printf("Clock advanced by %d h (total offset: %ld h).\n", n, sim_offset_hours);
            break;
        case 7: generate_report(&list, current_time()); break;
        case 8: log_print(); break;
        case 9:
            n = save_incidents(&list, DATA_FILE);
            if (n >= 0) printf("Saved %d incident(s) to %s.\n", n, DATA_FILE);
            else        printf("Error: could not write %s.\n", DATA_FILE);
            break;
        case 10: {
            /* Replace the current list with the saved one (no duplicates). */
            size_t old_count = list.count;
            int old_next_id = list.next_id;

            list.count = 0;
            list.next_id = 1;
            n = load_incidents(&list, DATA_FILE);
            if (n >= 0) {
                printf("Loaded %d incident(s) (replaced current list).\n", n);
            } else {                /* no file: keep what we had */
                list.count = old_count;
                list.next_id = old_next_id;
                printf("No save file found. Current list kept.\n");
            }
            break;
        }
        case 0: break;
        }
    } while (choice != 0);

    if (save_incidents(&list, DATA_FILE) >= 0)
        printf("Data saved to %s. Goodbye!\n", DATA_FILE);
    list_free(&list);
#ifdef _WIN32
    printf("\nPress Enter to close...");   /* keeps the window open on double-click */
    getchar();
#endif
    return EXIT_SUCCESS;
}
