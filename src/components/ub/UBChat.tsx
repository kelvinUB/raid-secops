import { useState, useRef, useEffect } from 'react'
import { useApp } from '../../context/AppContext'
import { useNavigate } from 'react-router-dom'
import { fetchAlerts } from '../../lib/api'
import type { AlertRow, UserRole } from '../../lib/api'
import { pct, roleLabel } from '../../lib/utils'

interface Message {
  who:  'ai' | 'user'
  text: string
}

const SUGGESTIONS = [
  'Summarize this alert',
  'Explain the MITRE technique',
  'Why was this flagged for human review?',
  'What should the SOC Analyst do next?',
  'What should the Security Engineer validate?',
  'What is the business impact for CISO / GRC?',
  'What does a negative Isolation Forest score mean?',
  'Show me all open ATTACK alerts',
]

// ── Generate response based on real alert data ────────────────
function generateResponse(
  query: string,
  alert: any,
  role: UserRole | null,
  openAttacks: AlertRow[]
): string {
  const q = query.toLowerCase().trim()

  if (q.includes('summarize') || q.includes('summarise')) {
    if (!alert) return 'No alert loaded. Open an alert from the Alerts Queue first, then come back.'
    const scores = alert.modelScores || {}
    return [
      `Alert Summary — ${alert.sampleId || alert.sample_id}`,
      ``,
      `Status:         ${alert.status}`,
      `Confidence:     ${pct(alert.confidence)}`,
      `Attack Type:    ${alert.attackType || alert.attack_type || '—'}`,
      `MITRE:          ${alert.mitreTechnique || alert.mitre_technique || '—'}`,
      `Source SIEM:    ${alert.sourceSiem || alert.source_siem || '—'}`,
      `Assigned Role:  ${roleLabel(alert.assignedRole || alert.assigned_role)}`,
      `Investigation:  ${alert.investigationStatus || alert.investigation_status}`,
      `Defer to Human: ${alert.deferToHuman || alert.defer_to_human ? 'Yes — human review required' : 'No — pipeline confidence sufficient'}`,
      ``,
      `ML Pipeline:`,
      `  Isolation Forest Score:   ${scores.isolationForestScore?.toFixed(3) ?? (alert.isolation_forest_score != null ? Number(alert.isolation_forest_score).toFixed(3) : '—')}`,
      `  Random Forest Confidence: ${pct(scores.randomForestConfidence ?? alert.random_forest_confidence ?? 0)}`,
      `  Models Agree:             ${(scores.modelsAgree ?? alert.models_agree) ? 'Yes' : 'No'}`,
    ].join('\n')
  }

  if (q.includes('mitre')) {
    if (!alert) return 'No alert loaded. Open an alert first.'
    const mitre = alert.mitreTechnique || alert.mitre_technique || '—'
    if (mitre === '—') return 'No MITRE technique assigned to this alert.'
    const explanations: Record<string, string> = {
      'T1021': 'Remote Services — adversaries use legitimate remote services (RDP, SSH, SMB) to move laterally across the network.',
      'T1003': 'OS Credential Dumping — adversaries extract credentials from LSASS memory, SAM database, or NTDS.',
      'T1048': 'Exfiltration Over Alternative Protocol — data moved out via DNS tunnelling, ICMP, or other non-standard channels.',
      'T1068': 'Exploitation for Privilege Escalation — kernel or application exploits used to gain elevated privileges.',
      'T1190': 'Exploit Public-Facing Application — adversaries exploit vulnerabilities in internet-facing applications.',
      'T1498': 'Network Denial of Service — flooding attacks to disrupt service availability. Monitor for abnormal traffic volume.',
      'T1595': 'Active Scanning — adversaries probe the network for open ports and vulnerabilities before attacking.',
      'T1078': 'Valid Accounts — use of legitimate credentials to blend in with normal traffic.',
      'T1059': 'Command and Scripting Interpreter — execution via PowerShell, cmd, bash, or other interpreters.',
      'T1543': 'Create or Modify System Process — persistence via services or launch daemons.',
      'T1210': 'Exploitation of Remote Services — targeting vulnerabilities in SMB, RDP, or other remote protocols.',
      'T1046': 'Network Service Discovery — adversaries scan for open services and ports on the network.',
      'T1203': 'Exploitation for Client Execution — exploiting vulnerabilities in client applications.',
    }
    const code = mitre.split('–')[0].split('—')[0].trim()
    const match = Object.entries(explanations).find(([k]) => code.includes(k))
    return match
      ? `MITRE ${mitre}\n\n${match[1]}\n\nThis mapping was assigned by the Random Forest classifier based on the attack category of the network event.`
      : `MITRE ${mitre}\n\nThis technique was mapped by the Random Forest classifier based on features extracted from the raw SIEM event. Visit attack.mitre.org for full details.`
  }

  if (q.includes('flagged') || q.includes('human review')) {
    if (!alert) return 'No alert loaded. Open an alert first.'
    const defer = alert.deferToHuman || alert.defer_to_human
    if (!defer) return `Alert ${alert.sampleId || alert.sample_id} was NOT flagged for human review.\n\nThe pipeline had sufficient confidence (${pct(alert.confidence)}) to classify this automatically.`
    return [
      `Alert ${alert.sampleId || alert.sample_id} was flagged for Human Review.`,
      ``,
      `Reasons:`,
      `• Model confidence (${pct(alert.confidence)}) fell in the uncertain band (45%–60%)`,
      `• OR the two models gave opposite verdicts`,
      ``,
      `A human must review and decide the action before any response is taken.`,
      `Assigned to: ${roleLabel(alert.assignedRole || alert.assigned_role)}`,
    ].join('\n')
  }

  if (q.includes('soc analyst') || (q.includes('analyst') && !q.includes('engineer'))) {
    if (!alert) return 'No alert loaded. Open an alert first.'
    const rec = alert.recommendations?.analyst || alert.rec_analyst || 'No recommendation available.'
    return `SOC Analyst Recommendation — ${alert.sampleId || alert.sample_id}:\n\n${rec}`
  }

  if (q.includes('security engineer') || q.includes('engineer')) {
    if (!alert) return 'No alert loaded. Open an alert first.'
    const rec = alert.recommendations?.engineer || alert.rec_engineer || 'No recommendation available.'
    return `Security Engineer Recommendation — ${alert.sampleId || alert.sample_id}:\n\n${rec}`
  }

  if (q.includes('ciso') || q.includes('grc') || q.includes('business impact')) {
    if (!alert) return 'No alert loaded. Open an alert first.'
    const rec = alert.recommendations?.grc || alert.rec_grc || 'No recommendation available.'
    return `CISO / GRC Recommendation — ${alert.sampleId || alert.sample_id}:\n\n${rec}`
  }

  if (q.includes('isolation forest') || q.includes('negative')) {
    const score = alert?.modelScores?.isolationForestScore ?? alert?.isolation_forest_score
    const specific = score != null
      ? `\n\nFor this alert: IF score = ${Number(score).toFixed(3)} — ${Number(score) < 0 ? 'Anomalous — deviates from normal traffic.' : 'Normal — within expected baseline.'}`
      : ''
    return `Isolation Forest scores range from -1 to +1.\n\n• Negative score — anomalous (isolated quickly by the trees)\n• Positive score — normal (blends with training baseline)\n\nIn RAID-SecOps:\n• Score < 0     — anomaly flag set\n• Score < -0.2  — high-priority anomaly${specific}`
  }

  if (q.includes('open attack') || q.includes('show') || q.includes('all attack')) {
    if (openAttacks.length === 0) return 'No open ATTACK alerts found.'
    return [
      `Open ATTACK alerts (${openAttacks.length} total):`,
      ``,
      ...openAttacks.slice(0, 10).map(a =>
        `• ${a.sampleId} — ${a.attackType || '—'} (${pct(a.confidence)}) — ${a.investigationStatus}`
      ),
      openAttacks.length > 10 ? `\n...and ${openAttacks.length - 10} more.` : '',
    ].join('\n')
  }

  return `I can help with: summarizing alerts, explaining MITRE techniques, human review reasons, role recommendations, and Isolation Forest scores.\n\nTry one of the suggestion buttons below, or open an alert from the Alerts Queue first for full context.`
}

// ── Main UBChat component ─────────────────────────────────────
export function UBChat() {
  const { selectedAlert, role } = useApp()
  const navigate                = useNavigate()
  const alert = selectedAlert as any

  const [messages, setMessages] = useState<Message[]>([
    {
      who: 'ai',
      text: "Hello, I'm UB — the RAID-SecOps decision support assistant.\n\nI can help you understand alert model outputs, MITRE techniques, pipeline behaviour, and role-based recommendations.\n\nTip: Open an alert from the Alerts Queue first to load its context, then ask me questions about it.",
    },
  ])
  const [input,       setInput]       = useState('')
  const [loading,     setLoading]     = useState(false)
  const [openAttacks, setOpenAttacks] = useState<AlertRow[]>([])
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchAlerts({ status: 'ATTACK' })
      .then((data) => setOpenAttacks(data.filter((a) => a.investigationStatus !== 'closed')))
      .catch(() => {})
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = (text: string) => {
    if (!text.trim()) return
    const userMsg: Message = { who: 'user', text }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)
    setTimeout(() => {
      try {
        const reply = generateResponse(text, alert, role, openAttacks)
        setMessages((prev) => [...prev, { who: 'ai', text: reply }])
      } catch (e) {
        setMessages((prev) => [...prev, { who: 'ai', text: 'Something went wrong generating a response. Try again.' }])
      } finally {
        setLoading(false)
      }
    }, 400)
  }

  return (
    <div className="flex flex-col max-w-2xl">
      <div
        className="bg-white border border-gray-200 rounded-xl shadow-md flex flex-col"
        style={{ height: 'calc(100vh - 52px - 48px - 16px)', minHeight: 440 }}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-100">
          <div className="w-8 h-8 bg-[#0e1726] rounded-lg flex items-center justify-center text-[13px] font-bold text-[#93c5fd]">
            UB
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[13px] font-bold text-gray-900">UB Assistant</div>
            <div className="text-[10px] text-gray-400 truncate">
              {alert
                ? `Context loaded: ${alert.sampleId || alert.sample_id} · ${alert.attackType || alert.attack_type || '—'} · ${pct(alert.confidence)} confidence`
                : 'No alert loaded — open an alert from the Alerts Queue'}
            </div>
          </div>
          <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold bg-green-50 text-green-700 border border-green-200 px-2.5 py-0.5 rounded-md shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 live-dot" />
            Active
          </span>
        </div>

        {/* Context banner */}
        {!alert && (
          <div className="mx-4 mt-3 flex items-start gap-2.5 bg-blue-50 border border-blue-200 rounded-lg px-3.5 py-2.5">
            <span className="text-blue-500 text-[13px] shrink-0 mt-0.5">i</span>
            <div className="flex-1">
              <div className="text-[11px] font-semibold text-blue-800">No alert context loaded</div>
              <div className="text-[11px] text-blue-600 mt-0.5">
                Go to the{' '}
                <button onClick={() => navigate('/alerts')} className="underline hover:text-blue-800">
                  Alerts Queue
                </button>
                , open an alert, then come back. UB will have full context to answer your questions.
              </div>
            </div>
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-4 py-4 flex flex-col gap-3">
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.who === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[78%] px-3.5 py-2.5 text-[12px] leading-relaxed whitespace-pre-wrap ${
                m.who === 'user'
                  ? 'bg-[#0e1726] text-blue-100 rounded-xl rounded-br-sm'
                  : 'bg-gray-50 text-gray-600 border border-gray-200 rounded-xl rounded-bl-sm'
              }`}>
                {m.text}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-gray-50 border border-gray-200 rounded-xl rounded-bl-sm px-4 py-3 flex gap-1.5 items-center">
                <span className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-gray-100 flex flex-col gap-2.5">
          <div className="flex flex-wrap gap-1.5">
            {SUGGESTIONS.map((s) => (
              <button
                key={s}
                onClick={() => send(s)}
                disabled={loading}
                className="border border-gray-200 rounded-full px-2.5 py-1 text-[11px] text-gray-400 bg-white hover:bg-gray-50 hover:text-gray-700 transition-colors disabled:opacity-40"
              >
                {s}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400 bg-white"
              placeholder="Ask UB about this alert, MITRE technique, model output..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !loading) send(input) }}
              disabled={loading}
            />
            <button
              onClick={() => send(input)}
              disabled={loading || !input.trim()}
              className="px-4 py2 bg-[#0e1726] text-white text-[12px] font-medium rounded-lg hover:bg-[#1c2d45] transition-colors disabled:opacity-40"
            >
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
