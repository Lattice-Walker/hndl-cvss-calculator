// Hover explanations for every control on the page.
//
// Each entry is one sentence of definition followed by a concrete example.
// app.js prefixes the metric code, so the letters dropped from the visible
// labels ("Attack Vector (AV)" is rendered "Attack Vector") remain one hover
// away. Base metrics are written twice, because the same metric means a
// different thing under an active attack than under passive collection.
(function () {
  "use strict";

  // ---- Deprecation vector: an active attacker on a live TLS session -------

  var DEP = {
    AV: {
      text: "Where the attacker has to be, relative to the endpoint, to run the active attack; more remote scores higher because more people can reach it. Example: a public HTTPS listener is Network, a TLS service bound to loopback is Local.",
      options: {
        N: "Reachable across routed networks up to the whole internet, with no requirement to sit anywhere in particular. Example: a public HTTPS endpoint still offering TLS 1.0 CBC suites to anything that can route to it.",
        A: "Limited to the same logical network or administrative domain. Example: an internal API that only accepts connections originating on the corporate LAN or a site-to-site VPN.",
        L: "Requires a local account, a shell, or terminal access on the host. Example: a TLS listener bound to 127.0.0.1 and reachable only from the machine itself.",
        P: "Requires physically touching the device. Example: a management interface on an appliance that only answers over a console cable."
      }
    },
    AC: {
      text: "Whether the attacker must defeat a countermeasure or land a condition they can influence but not control. Example: a downgrade the server always accepts is Low, a timing oracle needing thousands of measurements is High.",
      options: {
        L: "The attack works on the first try, with nothing to evade. Example: the server accepts the deprecated cipher suite every time it is offered.",
        H: "The attacker must beat a mitigation, win a race, or grind through a measurable search. Example: a Lucky13 timing oracle taking thousands of carefully timed requests to recover a single byte."
      }
    },
    AT: {
      text: "Conditions outside the attacker's control that have to hold before the attack can work at all. Example: needing a victim browser to keep replaying a request is a requirement, a flaw that fires on any connection has none.",
      options: {
        N: "No precondition beyond reaching the endpoint. Example: the deprecated suite is offered to every client that asks for it.",
        P: "A condition the attacker cannot arrange must already be true. Example: the attacker must hold a machine-in-the-middle position while the victim generates repeated requests carrying the target cookie."
      }
    },
    PR: {
      text: "The level of account the attacker needs before the flaw is reachable. Example: a handshake flaw needs none, because it fires before anyone authenticates.",
      options: {
        N: "No account at all. Example: the flaw is in the TLS handshake, which happens before any login.",
        L: "An ordinary user account. Example: the vulnerable legacy endpoint is only exposed once a standard user has signed in.",
        H: "Administrative or equivalent rights. Example: the deprecated listener only appears on an operator console behind an admin role."
      }
    },
    UI: {
      text: "Whether somebody other than the attacker has to do something for the attack to land. Example: a padding oracle driven by a victim's open tab needs interaction, attacking the handshake directly does not.",
      options: {
        N: "The attacker acts alone. Example: they open the connection themselves and attack the handshake.",
        P: "A victim must carry on doing something ordinary, unaware. Example: the user leaves a tab open that keeps re-sending the session cookie the oracle is extracting.",
        A: "The victim must be deliberately steered into an unusual action. Example: they have to be lured to an attacker-controlled page that drives the requests."
      }
    },
    VC: {
      text: "How much of this endpoint's protected data the active attack exposes. Example: a padding oracle recovering one cookie over several hours is Low, a flaw handing over the whole session is High.",
      options: {
        H: "All of the protected data, or the part of it that matters most, is exposed. Example: the flaw yields the session keys outright, so the entire exchange is readable.",
        L: "Some data leaks, with little control over which parts. Example: a byte-at-a-time padding oracle that in practice recovers one cookie before the session rotates.",
        N: "Nothing is disclosed. Example: a renegotiation flaw that lets traffic be injected but never read."
      }
    },
    VI: {
      text: "Whether the active attacker can alter data on this endpoint. Example: an in-path attacker rewriting a request body is High, one who can only truncate a record is Low.",
      options: {
        H: "Data can be modified at will, or the modification is serious in itself. Example: the attacker rewrites request bodies in transit and the endpoint accepts them.",
        L: "Modification is possible but limited or unreliable. Example: a downgrade lets a record be truncated, but not chosen or forged.",
        N: "Nothing can be modified. Example: a purely passive disclosure flaw."
      }
    },
    VA: {
      text: "Whether the attack can degrade or deny the service itself. Example: a handshake flaw that crashes the listener is High, one that merely forces expensive renegotiations is Low.",
      options: {
        H: "The service can be fully denied, or denied for as long as the attacker likes. Example: a malformed handshake that reliably crashes the TLS terminator.",
        L: "Performance or availability is reduced without being denied. Example: repeated forced renegotiations that slow the endpoint for everyone.",
        N: "Availability is untouched. Example: the attack is silent and the service keeps serving normally."
      }
    },
    SC: {
      text: "Confidentiality lost on systems other than this endpoint, as a consequence of the attack. Example: a recovered cookie that opens an admin session on a back-office application.",
      options: {
        H: "Another system's data is fully or seriously exposed as a result. Example: the extracted cookie grants an authenticated session on an internal admin console.",
        L: "Limited exposure elsewhere. Example: a leaked header reveals internal hostnames and software versions.",
        N: "Nothing beyond this endpoint is disclosed. Example: the endpoint terminates TLS for itself only and holds no onward credentials."
      }
    },
    SI: {
      text: "Integrity lost on systems other than this endpoint, as a consequence. Example: a stolen service credential used to rewrite records in a downstream database.",
      options: {
        H: "Another system's data can be modified at will as a result. Example: a recovered service account token used to alter records in a connected database.",
        L: "Limited or unreliable modification elsewhere. Example: a leaked identifier lets one field be changed through a downstream form.",
        N: "No onward integrity impact. Example: nothing recovered here authenticates to anything else."
      }
    },
    SA: {
      text: "Availability lost on systems other than this endpoint, as a consequence. Example: credentials recovered here used to lock a downstream account.",
      options: {
        H: "Another system can be fully denied as a result. Example: a recovered administrative credential used to shut down a dependent service.",
        L: "Another system is degraded but not denied. Example: recovered access is enough to exhaust a downstream rate limit.",
        N: "No onward availability impact. Example: nothing recovered here can reach another system."
      }
    }
  };

  // ---- Harvest vector: passive collection now, decryption later -----------

  var HARV = {
    AV: {
      text: "Where the collector has to be to copy this endpoint's ciphertext off the wire. Example: sessions crossing a transit provider are Network, traffic that never leaves a switch you own is Adjacent.",
      options: {
        N: "The ciphertext can be copied anywhere along an internet path. Example: sessions traversing a transit provider or a subsea cable where a passive tap records everything that passes.",
        A: "Collection needs a position on the same network segment. Example: a span port on an office switch carrying an internal service's traffic.",
        L: "Collection needs an account on the host itself. Example: a loopback-only service whose traffic never reaches a wire at all.",
        P: "Collection needs physical access to the medium. Example: splicing a fibre run inside a building to mirror it."
      }
    },
    AC: {
      text: "Fixed at Low on this vector: recording ciphertext defeats no countermeasure and can always be retried. Example: mirroring a port and writing the capture to disk works the first time and every time.",
      options: {
        L: "Copying frames off a tap succeeds every time and evades nothing. Example: a capture process writing to disk for as long as the storage lasts.",
        H: "Would describe an active attack rather than collection, which is why this vector does not offer it. Example: a timing oracle belongs on the deprecation vector."
      }
    },
    AT: {
      text: "Whether the collector still has to obtain a position on the path, or already occupies one. Example: traffic crossing a jurisdiction where bulk collection is routine needs nothing further.",
      options: {
        N: "No precondition: the traffic is already within reach of a collector. Example: the sessions cross international transit, or a jurisdiction in which bulk collection is a standing practice.",
        P: "A position on the path must first be obtained. Example: a transit provider must be compromised or compelled before the sessions of interest occur."
      }
    },
    PR: {
      text: "Fixed at None on this vector: copying traffic in transit requires no account on the endpoint. Example: a tap upstream of the load balancer never authenticates to anything.",
      options: {
        N: "Recording requires nothing from the endpoint. Example: the collector never sends a packet to it.",
        L: "Would mean collection requires a user account, which passive capture never does. Example: this belongs on the deprecation vector instead.",
        H: "Would mean collection requires administrative rights, which passive capture never does. Example: this belongs on the deprecation vector instead."
      }
    },
    UI: {
      text: "Fixed at None on this vector: nobody has to do anything for traffic to be recorded. Example: the capture runs whether or not any user is active that day.",
      options: {
        N: "No victim action is involved. Example: the collector records whatever crosses the tap, with no one aware of it.",
        P: "Would require a victim to act, which passive collection does not. Example: this belongs on the deprecation vector instead.",
        A: "Would require a victim to be steered, which passive collection does not. Example: this belongs on the deprecation vector instead."
      }
    },
    VC: {
      text: "How much of the recorded traffic becomes readable once the key exchange is broken. Example: a day of captured sessions decrypting in both directions, headers and bodies alike, is High.",
      options: {
        H: "Every recorded session decrypts in full. Example: the whole capture yields requests, responses, headers and bodies once Shor's algorithm recovers the key exchange.",
        L: "Only part of the traffic is recoverable. Example: only the minority of sessions that negotiated the non-forward-secret suite were captured, and they carry little.",
        N: "Nothing is recoverable. Example: every recorded session already used a hybrid key exchange that stays out of reach."
      }
    },
    VI: {
      text: "Fixed at None on this vector: decrypting a recording later cannot change what was sent. Example: reading a 2026 session in 2038 does not alter a byte of it.",
      options: {
        H: "Would mean the recording can be modified, which retrospective decryption cannot do. Example: put in-path tampering on the deprecation vector.",
        L: "Would mean partial modification, which retrospective decryption cannot do. Example: put in-path tampering on the deprecation vector.",
        N: "A capture made in the past cannot be altered by decrypting it later. Example: the endpoint's data is read, never rewritten."
      }
    },
    VA: {
      text: "Fixed at None on this vector: passive collection denies nothing. Example: the endpoint serves normally throughout, unaware it is being recorded.",
      options: {
        H: "Would mean the service can be denied, which passive collection never does. Example: put denial of service on the deprecation vector.",
        L: "Would mean the service is degraded, which passive collection never does. Example: put degradation on the deprecation vector.",
        N: "Collection is invisible to the endpoint. Example: throughput and error rates are unchanged while the capture runs."
      }
    },
    SC: {
      text: "Confidentiality lost on other systems once the recording is decrypted. Example: captured sessions carrying a long-lived API token that still works years later.",
      options: {
        H: "Decrypted material fully opens another system. Example: the sessions carry a bearer token or key material that is still valid when the decryption happens.",
        L: "Decrypted material partially exposes another system. Example: internal hostnames and service topology are revealed, but no credential.",
        N: "The sessions carry nothing that reaches another system. Example: an anonymous public feed with no credentials in flight."
      }
    },
    SI: {
      text: "Integrity lost on other systems once decrypted material is put to use. Example: a recovered signing key used to forge requests to a partner's API.",
      options: {
        H: "Decrypted material lets another system's data be modified at will. Example: a long-lived service credential in the capture is still accepted and is used to rewrite records.",
        L: "Limited modification elsewhere becomes possible. Example: a recovered identifier allows one downstream field to be changed.",
        N: "Nothing in the capture enables modification elsewhere. Example: the sessions carry read-only public content."
      }
    },
    SA: {
      text: "Availability lost on other systems once decrypted material is put to use. Example: a recovered administrative credential used to shut down a dependent service.",
      options: {
        H: "Another system can be fully denied using what was decrypted. Example: recovered admin credentials still work and are used to disable it.",
        L: "Another system is degraded using what was decrypted. Example: recovered access is enough to exhaust a downstream quota.",
        N: "Nothing in the capture can deny another system. Example: no onward credentials are ever in flight."
      }
    }
  };

  // ---- Threat, environmental and supplemental (deprecation panel) ---------

  var OTHER = {
    E: {
      text: "How far real-world exploitation of this flaw has actually got. It is the one metric this page treats differently on each vector: it is locked out of the harvest vector, where the absence of a quantum computer is the premise rather than a mitigation. Example: a padding oracle with public tooling is Attacked.",
      options: {
        X: "Not Defined, which is not neutral: CVSS v4.0 scores it exactly as Attacked, the worst case. Example: leaving it unset on a flaw nobody has ever reported still scores as though it were being exploited today.",
        A: "Exploitation is happening, or a reliable weaponised exploit is available. Example: the padding oracle ships as a module in a public offensive toolkit.",
        P: "A proof of concept exists but no dependable attack. Example: a paper demonstrates the oracle in a lab against one specific stack.",
        U: "No exploit and no reported exploitation. Example: the suite is deprecated on principle, but no working attack against this configuration has been published."
      }
    },
    CR: {
      text: "How much the confidentiality of this data matters in your environment, which reweights the confidentiality impact. It describes the data, not the attack. Example: decades-long secrecy for medical records is High.",
      options: {
        X: "Not Defined, which CVSS v4.0 scores identically to High. Example: leaving it unset on a low-sensitivity feed still scores as though secrecy were critical, which is why this page asks for it explicitly on the harvest vector.",
        H: "Loss of confidentiality would be catastrophic for the organisation. Example: session transcripts holding personal or clinical data that must stay secret for thirty years.",
        M: "Loss would be serious but survivable. Example: internal telemetry that would embarrass the organisation without harming anyone.",
        L: "Loss would be a limited problem. Example: a public status feed that is encrypted out of habit rather than need."
      }
    },
    IR: {
      text: "How much the integrity of this data matters in your environment, which reweights the integrity impact. Example: a financial ledger is High, a cache of public content is Low.",
      options: {
        X: "Not Defined, which CVSS v4.0 scores identically to High. Example: leaving it unset assumes integrity is critical.",
        H: "Undetected modification would be catastrophic. Example: a payment instruction that is acted on without further checks.",
        M: "Modification would be serious but recoverable. Example: a reporting dataset that is reconciled monthly.",
        L: "Modification would be a limited problem. Example: a cache that is rebuilt from an authoritative source anyway."
      }
    },
    AR: {
      text: "How much the availability of this service matters in your environment, which reweights the availability impact. Example: an emergency dispatch system is High, a nightly batch report is Low.",
      options: {
        X: "Not Defined, which CVSS v4.0 scores identically to High. Example: leaving it unset assumes availability is critical.",
        H: "An outage would be catastrophic. Example: the endpoint fronts an emergency dispatch service.",
        M: "An outage would be serious but tolerable. Example: a customer portal with a published maintenance window.",
        L: "An outage would barely register. Example: a nightly batch report that can run late."
      }
    },
    S: {
      text: "Whether exploiting this flaw could hurt someone physically, in the IEC 61508 sense. Recorded only, it never moves the score. Example: an endpoint fronting a building access controller is Present.",
      options: {
        X: "Not evaluated. Example: nobody has assessed the safety dimension yet.",
        N: "Consequences are negligible in safety terms. Example: a marketing site where a breach harms no one physically.",
        P: "Consequences reach marginal, critical or catastrophic. Example: the endpoint fronts a controller for a door, a pump or a vehicle."
      }
    },
    AU: {
      text: "Whether an attacker can automate this across many targets end to end, from finding them to exploiting them. Recorded only, it never moves the score. Example: a scanner that sweeps a netblock and runs the oracle unattended is Yes.",
      options: {
        X: "Not evaluated. Example: nobody has assessed automatability yet.",
        N: "Some step needs a human. Example: the oracle needs an operator to choose a live session worth targeting.",
        Y: "The whole chain can be scripted. Example: a tool sweeps a range for the deprecated suite and runs the attack on every hit without supervision."
      }
    },
    R: {
      text: "How the system gets back to working after exploitation. Recorded only, it never moves the score. Example: disclosed key material is Irrecoverable, because it cannot be un-disclosed.",
      options: {
        X: "Not evaluated. Example: nobody has assessed recovery yet.",
        A: "The system restores itself. Example: the terminator restarts and resumes serving with no intervention.",
        U: "A person must intervene. Example: an operator has to rotate the certificate and reload the configuration by hand.",
        I: "The system cannot be restored to its previous state. Example: traffic that has already been harvested cannot be made secret again."
      }
    },
    V: {
      text: "How much value a single successful attack yields, which is about the target rather than the flaw. Recorded only, it never moves the score. Example: a shared TLS terminator for the whole estate is Concentrated.",
      options: {
        X: "Not evaluated. Example: nobody has assessed value density yet.",
        D: "Each compromised target is worth little on its own. Example: one user's session on a personal device.",
        C: "One target is worth a great deal. Example: the reverse proxy that terminates TLS for every service in the estate."
      }
    },
    RE: {
      text: "How much work it takes you to respond to this, from deciding to fix it to having fixed it. Recorded only, it never moves the score. Example: one config line and a reload is Low.",
      options: {
        X: "Not evaluated. Example: nobody has scoped the remediation yet.",
        L: "A quick, low-risk change. Example: removing the deprecated suite is one configuration line and a service reload.",
        M: "A planned change with some risk. Example: the change needs a maintenance window and regression testing against known clients.",
        H: "A substantial programme. Example: legacy embedded clients must be replaced in the field before the suite can be withdrawn."
      }
    },
    U: {
      text: "A pass-through urgency rating from whoever supplied the assessment, on a traffic-light scale. Recorded only, it never moves the score. Example: a vendor advisory marked Red.",
      options: {
        X: "Not evaluated. Example: the provider issued no urgency rating.",
        Clear: "Informational, no urgency. Example: the provider notes the deprecated suite without asking anyone to act.",
        Green: "Reduced urgency. Example: the provider suggests folding the change into the next scheduled release.",
        Amber: "Moderate urgency. Example: the provider asks for the change within the current quarter.",
        Red: "Highest urgency. Example: the provider asks for the deprecated suite to be withdrawn immediately."
      }
    }
  };

  // ---- Environmental modified base metrics --------------------------------
  // Same meaning as the base metric, applied to your own deployment, so the
  // base wording and its examples are reused rather than reinvented.

  var MODIFIED = {
    MAV: ["AV", "Attack Vector"], MAC: ["AC", "Attack Complexity"],
    MAT: ["AT", "Attack Requirements"], MPR: ["PR", "Privileges Required"],
    MUI: ["UI", "User Interaction"], MVC: ["VC", "Confidentiality"],
    MVI: ["VI", "Integrity"], MVA: ["VA", "Availability"],
    MSC: ["SC", "Subsequent Confidentiality"], MSI: ["SI", "Subsequent Integrity"],
    MSA: ["SA", "Subsequent Availability"]
  };

  Object.keys(MODIFIED).forEach(function (key) {
    var base = DEP[MODIFIED[key][0]];
    var name = MODIFIED[key][1];
    var entry = {
      text: "Your own deployment's value for " + name + ", which replaces the base value when this environment is scored. " + base.text,
      options: {
        X: "Not Defined, so the base value for " + name + " is used unchanged. Example: leave this alone unless your deployment genuinely differs from the supplier's assessment."
      }
    };
    Object.keys(base.options).forEach(function (v) {
      entry.options[v] = base.options[v];
    });
    OTHER[key] = entry;
  });

  OTHER.MSI.options.S = "Safety: the subsequent integrity failure has a physical safety consequence, which CVSS v4.0 treats as the most severe case of all. Example: falsified readings reaching a system that controls a pump or a door.";
  OTHER.MSA.options.S = "Safety: the subsequent availability failure has a physical safety consequence, which CVSS v4.0 treats as the most severe case of all. Example: an interlock that fails open because the system it depends on is unreachable.";

  function merge(base, extra) {
    var out = {};
    Object.keys(base).forEach(function (k) { out[k] = base[k]; });
    Object.keys(extra).forEach(function (k) { out[k] = extra[k]; });
    return out;
  }

  window.HELP = {
    dep: merge(DEP, OTHER),
    harv: merge(HARV, { CR: OTHER.CR })
  };
})();
