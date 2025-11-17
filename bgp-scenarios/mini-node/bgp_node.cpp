#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libbgp/bgp-fsm.h>
#include <libbgp/bgp-config.h>
#include <libbgp/fd-out-handler.h>
#include <libbgp/route-event-bus.h>
#include <libbgp/bgp-log-handler.h>
#include <libbgp/bgp-rib4.h>

static void usage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  Server: " << prog
        << " server <listen_port> <local_asn> <router_id> [scenario_file]\n"
        << "    e.g.  " << prog
        << " server 1179 34224 1.1.1.1 ../scenarios/generated/rv2_20230101_1h/node_34224.scenario\n\n"
        << "  Client: " << prog
        << " client <peer_ip> <peer_port> <local_asn> <router_id> <peer_asn> [scenario_file]\n"
        << "    e.g.  " << prog
        << " client 127.0.0.1 1179 65001 2.2.2.2 34224 ../scenarios/generated/rv2_20230101_1h/node_65001.scenario\n";
}

static uint32_t parse_ipv4(const std::string &s) {
    in_addr addr;
    std::memset(&addr, 0, sizeof(addr));
    if (inet_aton(s.c_str(), &addr) == 0) {
        std::cerr << "[node] Invalid IPv4 address: " << s << "\n";
        std::exit(1);
    }
    return addr.s_addr;
}

class MyLoghandler : public libbgp::BgpLogHandler {
public:
    explicit MyLoghandler(const std::string &name) : name_(name) {}
protected:
    void logImpl(const char *str) override {
        std::cerr << "[" << name_ << "] " << str;
    }
private:
    std::string name_;
};

struct NodeOptions {
    bool is_server;
    uint16_t listen_port;
    std::string peer_ip;
    uint16_t peer_port;
    uint32_t local_asn;
    uint32_t peer_asn;
    std::string router_id;
    bool has_scenario;
    std::string scenario_path;

    NodeOptions()
        : is_server(false),
          listen_port(0),
          peer_port(0),
          local_asn(0),
          peer_asn(0),
          has_scenario(false) {}
};

static NodeOptions parse_args(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        std::exit(1);
    }

    NodeOptions opt;
    std::string mode = argv[1];

    if (mode == "server") {
        if (argc != 5 && argc != 6) {
            usage(argv[0]);
            std::exit(1);
        }
        opt.is_server   = true;
        opt.listen_port = static_cast<uint16_t>(std::stoi(argv[2]));
        opt.local_asn   = static_cast<uint32_t>(std::stoul(argv[3]));
        opt.router_id   = argv[4];
        opt.peer_asn    = 0;
        if (argc == 6) {
            opt.has_scenario = true;
            opt.scenario_path = argv[5];
        }
    } else if (mode == "client") {
        if (argc != 7 && argc != 8) {
            usage(argv[0]);
            std::exit(1);
        }
        opt.is_server   = false;
        opt.peer_ip     = argv[2];
        opt.peer_port   = static_cast<uint16_t>(std::stoi(argv[3]));
        opt.local_asn   = static_cast<uint32_t>(std::stoul(argv[4]));
        opt.router_id   = argv[5];
        opt.peer_asn    = static_cast<uint32_t>(std::stoul(argv[6]));
        if (argc == 8) {
            opt.has_scenario = true;
            opt.scenario_path = argv[7];
        }
    } else {
        usage(argv[0]);
        std::exit(1);
    }

    return opt;
}

struct ScenarioEvent {
    double t_rel;
    std::string project;
    std::string collector;
    uint32_t peer_asn;
    std::string peer_ip;
    char msg_type;
    std::string prefix;
    std::string as_path;
    uint32_t origin_as;
    std::string communities;
};

static uint32_t parse_u32_soft(const std::string &s,
                               const char *field_name,
                               size_t lineno,
                               const std::string &path,
                               size_t &warn_count) {
    if (s.empty()) {
        if (warn_count < 5) {
            std::cerr << "[scenario] WARNING: empty " << field_name
                      << " at line " << lineno << " in " << path
                      << " -> using 0\n";
        }
        ++warn_count;
        return 0;
    }

    char *end = NULL;
    errno = 0;
    unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str() || errno == ERANGE) {
        if (warn_count < 5) {
            std::cerr << "[scenario] WARNING: non-numeric " << field_name
                      << "='" << s << "' at line " << lineno
                      << " in " << path << " -> using 0\n";
        }
        ++warn_count;
        return 0;
    }
    return static_cast<uint32_t>(v);
}

static bool load_scenario(const std::string &path,
                          std::vector<ScenarioEvent> &out) {
    std::ifstream in(path.c_str());
    if (!in) {
        std::cerr << "[scenario] ERROR: cannot open scenario file: " << path << "\n";
        return false;
    }

    std::string line;
    size_t lineno = 0;
    size_t malformed = 0;
    size_t numeric_warns = 0;

    while (std::getline(in, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#') continue;

        std::vector<std::string> flds;
        std::string tok;
        std::stringstream ss(line);
        while (std::getline(ss, tok, '|')) {
            flds.push_back(tok);
        }

        if (flds.size() < 9) {
            if (malformed < 10) {
                std::cerr << "[scenario] WARNING: malformed line "
                          << lineno << " in " << path
                          << " (got " << flds.size()
                          << " fields < 9), skipping.\n";
            }
            ++malformed;
            continue;
        }

        ScenarioEvent ev;
        try {
            ev.t_rel     = std::stod(flds[0]);
            ev.project   = flds[1];
            ev.collector = flds[2];

            ev.peer_asn  = parse_u32_soft(flds[3], "peer_asn", lineno, path, numeric_warns);
            ev.peer_ip   = flds[4];

            if (flds[5].empty()) {
                if (malformed < 10) {
                    std::cerr << "[scenario] WARNING: empty msg_type at line "
                              << lineno << " in " << path << ", skipping.\n";
                }
                ++malformed;
                continue;
            }
            ev.msg_type = flds[5][0];
            ev.prefix   = flds[6];
            ev.as_path  = flds[7];

            ev.origin_as = parse_u32_soft(flds[8], "origin_as", lineno, path, numeric_warns);

            ev.communities.clear();
            if (flds.size() >= 10) {
                ev.communities = flds[9];
                for (size_t i = 10; i < flds.size(); ++i) {
                    ev.communities.push_back('|');
                    ev.communities += flds[i];
                }
            }
        } catch (const std::exception &e) {
            if (malformed < 10) {
                std::cerr << "[scenario] WARNING: parse error at line "
                          << lineno << " in " << path
                          << " (" << e.what() << "), skipping.\n";
            }
            ++malformed;
            continue;
        }

        out.push_back(ev);
    }

    if (malformed > 10) {
        std::cerr << "[scenario] WARNING: " << malformed
                  << " malformed lines skipped in " << path << "\n";
    }
    if (numeric_warns > 5) {
        std::cerr << "[scenario] NOTE: " << numeric_warns
                  << " numeric warnings (non-numeric ASNs) in " << path
                  << " (treated as 0).\n";
    }

    std::cerr << "[scenario] Loaded " << out.size()
              << " events from " << path << "\n";
    return true;
}

struct RibEntry {
    std::string prefix;
    std::string as_path;
    uint32_t    origin_as;
    std::string communities;
    double      last_t;
};

static bool ensure_dir(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) return true;
        std::cerr << "[node] ERROR: path " << path << " exists and is not a directory\n";
        return false;
    }
    if (mkdir(path.c_str(), 0755) < 0) {
        if (errno == EEXIST) return true;
        std::cerr << "[node] ERROR: mkdir(" << path << "): " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

static void write_rib_file(const std::string &rib_path,
                           const std::map<std::string, RibEntry> &rib) {
    std::ofstream out(rib_path.c_str(), std::ios::out | std::ios::trunc);
    if (!out) {
        std::cerr << "[scenario] ERROR: cannot write RIB file " << rib_path << "\n";
        return;
    }
    for (const auto &kv : rib) {
        const RibEntry &re = kv.second;
        out << re.prefix << "|"
            << re.as_path << "|"
            << re.origin_as << "|"
            << re.communities << "|"
            << re.last_t
            << "\n";
    }
    out.flush();
}

static void play_scenario_and_log(std::vector<ScenarioEvent> events,
                                  bool is_server,
                                  uint32_t asn,
                                  libbgp::BgpRib4 *bgp_rib,
                                  libbgp::BgpLogHandler *logger,
                                  uint32_t nexthop4,
                                  const std::string &events_path,
                                  const std::string &rib_path) {
    const char *role = is_server ? "SERVER" : "CLIENT";
    std::ostringstream label_oss;
    label_oss << "[" << role << "-AS" << asn << "]";
    const std::string label = label_oss.str();

    if (events.empty()) {
        std::cerr << "[scenario] " << label
                  << " no events to play, returning.\n";
        return;
    }

    std::ofstream ev_log(events_path.c_str(), std::ios::out | std::ios::trunc);
    if (!ev_log) {
        std::cerr << "[scenario] " << label
                  << " ERROR: cannot open events log file " << events_path << "\n";
    }

    std::map<std::string, RibEntry> rib;
    std::set<std::string> bgp_known_prefixes;

    std::cerr << "[scenario] " << label
              << " BGP session ESTABLISHED. Starting playback of "
              << events.size() << " events.\n";

    double last_t = 0.0;

    try {
        for (size_t i = 0; i < events.size(); ++i) {
            const ScenarioEvent &ev = events[i];

            double delay = ev.t_rel - last_t;
            if (delay > 0) {
                std::this_thread::sleep_for(std::chrono::duration<double>(delay));
            }
            last_t = ev.t_rel;

            std::cerr << "[scenario] " << label
                      << " t=" << ev.t_rel << "s "
                      << (ev.msg_type == 'W' ? '-' : '+') << " "
                      << ev.prefix
                      << "  as_path={" << ev.as_path << "}"
                      << "  origin_as=" << ev.origin_as;
            if (!ev.communities.empty()) {
                std::cerr << "  comms={" << ev.communities << "}";
            }
            std::cerr << "\n";

            if (ev_log) {
                ev_log << ev.t_rel << "|"
                       << role << "|"
                       << asn << "|"
                       << ev.msg_type << "|"
                       << ev.prefix << "|"
                       << ev.as_path << "|"
                       << ev.origin_as << "|"
                       << ev.communities
                       << "\n";
                ev_log.flush();
            }

            if (ev.msg_type == 'A') {
                RibEntry &re = rib[ev.prefix];
                re.prefix      = ev.prefix;
                re.as_path     = ev.as_path;
                re.origin_as   = ev.origin_as;
                re.communities = ev.communities;
                re.last_t      = ev.t_rel;
            } else if (ev.msg_type == 'W') {
                auto it = rib.find(ev.prefix);
                if (it != rib.end()) {
                    rib.erase(it);
                }
            }

            if (bgp_rib) {
                size_t slash = ev.prefix.find('/');
                if (slash == std::string::npos) {
                    std::cerr << "[scenario] " << label
                              << " WARNING: invalid prefix format '" << ev.prefix
                              << "', skipping BGP injection.\n";
                } else {
                    std::string ip_str  = ev.prefix.substr(0, slash);
                    std::string len_str = ev.prefix.substr(slash + 1);
                    int plen = 0;
                    try {
                        plen = std::stoi(len_str);
                    } catch (const std::exception &) {
                        std::cerr << "[scenario] " << label
                                  << " WARNING: invalid prefix length in '" << ev.prefix
                                  << "', skipping BGP injection.\n";
                        plen = -1;
                    }

                    if (plen >= 0 && plen <= 32) {
                        libbgp::Prefix4 pfx(ip_str.c_str(), plen);

                        if (ev.msg_type == 'A') {
                            if (bgp_known_prefixes.count(ev.prefix)) {
                                bgp_rib->withdraw(0, pfx);
                            }
                            bgp_rib->insert(logger, pfx, nexthop4);
                            bgp_known_prefixes.insert(ev.prefix);
                        } else if (ev.msg_type == 'W') {
                            bgp_rib->withdraw(0, pfx);
                            bgp_known_prefixes.erase(ev.prefix);
                        }
                    }
                }
            }

            write_rib_file(rib_path, rib);

            std::cerr << "[scenario] " << label
                      << " Loc-RIB size now = " << rib.size() << " routes\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "[scenario] " << label
                  << " EXCEPTION in scenario thread: " << e.what() << "\n";
    }

    std::cerr << "[scenario] " << label
              << " scenario playback finished at t=" << last_t << "s.\n";
}

int main(int argc, char **argv) {
    NodeOptions opt = parse_args(argc, argv);

    int sockfd = -1;

    if (opt.is_server) {
        int server_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd < 0) {
            std::cerr << "[node] socket(): " << strerror(errno) << "\n";
            return 1;
        }

        int yes = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(opt.listen_port);

        if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "[node] bind(): " << strerror(errno) << "\n";
            ::close(server_fd);
            return 1;
        }

        if (::listen(server_fd, 1) < 0) {
            std::cerr << "[node] listen(): " << strerror(errno) << "\n";
            ::close(server_fd);
            return 1;
        }

        std::cerr << "[node] Listening on 0.0.0.0:" << opt.listen_port << " ...\n";

        sockaddr_in caddr;
        std::memset(&caddr, 0, sizeof(caddr));
        socklen_t clen = sizeof(caddr);
        sockfd = ::accept(server_fd, reinterpret_cast<sockaddr*>(&caddr), &clen);
        if (sockfd < 0) {
            std::cerr << "[node] accept(): " << strerror(errno) << "\n";
            ::close(server_fd);
            return 1;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &caddr.sin_addr, ip_str, sizeof(ip_str));
        std::cerr << "[node] Accepted connection from " << ip_str
                  << ":" << ntohs(caddr.sin_port) << "\n";

        ::close(server_fd);
    } else {
        sockfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd < 0) {
            std::cerr << "[node] socket(): " << strerror(errno) << "\n";
            return 1;
        }

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(opt.peer_port);
        addr.sin_addr.s_addr = inet_addr(opt.peer_ip.c_str());

        std::cerr << "[node] Connecting to " << opt.peer_ip
                  << ":" << opt.peer_port << " ...\n";
        if (::connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "[node] connect(): " << strerror(errno) << "\n";
            ::close(sockfd);
            return 1;
        }
        std::cerr << "[node] Connected.\n";
    }

    libbgp::BgpConfig cfg;

    MyLoghandler logger(opt.is_server ? "BGP-SRV" : "BGP-CLI");
    logger.setLogLevel(libbgp::DEBUG);

    libbgp::RouteEventBus bus;
    libbgp::BgpRib4        rib(&logger);

    uint32_t rid_and_nexthop = parse_ipv4(opt.router_id);

    libbgp::FdOutHandler out_handler(sockfd);

    cfg.out_handler = &out_handler;
    cfg.log_handler = &logger;

    cfg.asn       = opt.local_asn;
    cfg.peer_asn  = opt.peer_asn;
    cfg.router_id = rid_and_nexthop;

    cfg.default_nexthop4        = rid_and_nexthop;
    cfg.forced_default_nexthop4 = true;

    cfg.no_nexthop_check4 = true;
    cfg.no_nexthop_check6 = true;

    cfg.mp_bgp_ipv4 = false;
    cfg.mp_bgp_ipv6 = false;

    cfg.rib4    = &rib;
    cfg.rev_bus = &bus;

    std::cerr << "[node] BGP FSM starting. "
              << "Local ASN=" << cfg.asn
              << " Router-ID=" << opt.router_id
              << " Peer ASN=" << cfg.peer_asn << "\n";

    libbgp::BgpFsm fsm(cfg);

    int start_rc = fsm.start();
    if (start_rc < 0) {
        std::cerr << "[node] ERROR: BgpFsm::start() returned " << start_rc << "\n";
        ::close(sockfd);
        return 1;
    } else {
        std::cerr << "[node] BgpFsm::start() ok, rc=" << start_rc << "\n";
    }

    std::string base_logs_dir = "logs";
    std::string events_dir = base_logs_dir + "/events";
    std::string ribs_dir   = base_logs_dir + "/ribs";

    if (!ensure_dir(base_logs_dir)) {
        std::cerr << "[node] ERROR: cannot ensure logs dir\n";
    }
    if (!ensure_dir(events_dir)) {
        std::cerr << "[node] ERROR: cannot ensure events dir\n";
    }
    if (!ensure_dir(ribs_dir)) {
        std::cerr << "[node] ERROR: cannot ensure ribs dir\n";
    }

    std::ostringstream ev_name;
    ev_name << events_dir << "/node_" << cfg.asn << "_" << (opt.is_server ? "srv" : "cli") << ".events.log";
    std::ostringstream rib_name;
    rib_name << ribs_dir << "/node_" << cfg.asn << "_" << (opt.is_server ? "srv" : "cli") << ".rib.log";

    std::thread scenario_thread;
    bool have_scenario_thread = false;

    if (opt.has_scenario) {
        std::vector<ScenarioEvent> events;
        if (load_scenario(opt.scenario_path, events)) {
            bool     is_srv_flag = opt.is_server;
            uint32_t asn_val     = cfg.asn;

            scenario_thread = std::thread(
                play_scenario_and_log,
                events,
                is_srv_flag,
                asn_val,
                &rib,
                &logger,
                rid_and_nexthop,
                ev_name.str(),
                rib_name.str()
            );
            have_scenario_thread = true;
        } else {
            std::cerr << "[scenario] ERROR: scenario disabled due to load failure.\n";
        }
    }

    uint8_t buf[4096];

    while (true) {
        ssize_t n = ::recv(sockfd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            std::cerr << "[node] recv(): " << strerror(errno) << "\n";
            break;
        }
        if (n == 0) {
            std::cerr << "[node] Peer closed connection.\n";
            break;
        }

        ssize_t consumed = fsm.run(buf, static_cast<size_t>(n));
        if (consumed < 0) {
            std::cerr << "[node] ERROR: BgpFsm::run() returned " << consumed << "\n";
            break;
        }
    }

    fsm.stop();
    ::close(sockfd);

    if (have_scenario_thread && scenario_thread.joinable()) {
        scenario_thread.join();
    }

    std::cerr << "[node] Exiting.\n";
    return 0;
}

