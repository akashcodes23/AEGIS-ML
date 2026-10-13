import { create } from 'zustand'

const useAlertStore = create((set) => ({
  alerts: [],
  incidents: [],
  graphData: { nodes: [], edges: [] },
  stats: {
    total_events: 0,
    events_per_second: 0,
    total_alerts: 0,
    alerts_by_severity: {},
    false_positive_rate: 0,
    current_file: null,
    analysis_complete: false,
  },
  simulationRunning: false,
  selectedIncident: null,

  setAlerts: (alerts) =>
    set({ alerts: Array.isArray(alerts) ? alerts.slice(0, 200) : [] }),

  setIncidents: (incidents) =>
    set({ incidents: Array.isArray(incidents) ? incidents : [] }),

  addAlert: (alert) =>
    set((state) => {
      const alertId = alert.alert_id || alert.event_id
      if (alertId && state.alerts.some((a) => (a.alert_id || a.event_id) === alertId)) {
        return state
      }
      return {
        alerts: [alert, ...state.alerts].slice(0, 200),
      }
    }),

  addIncident: (inc) =>
    set((state) => {
      const incId = inc.incident_id || inc.event_id
      if (incId && state.incidents.some((i) => (i.incident_id || i.event_id) === incId)) {
        return state
      }
      return {
        incidents: [inc, ...state.incidents],
      }
    }),

  updateIncident: (inc) =>
    set((state) => {
      const incId = inc.incident_id || inc.event_id
      const idx = state.incidents.findIndex((i) => (i.incident_id || i.event_id) === incId)
      if (idx >= 0) {
        const next = [...state.incidents]
        next[idx] = { ...next[idx], ...inc }
        return { incidents: next }
      }
      return { incidents: [inc, ...state.incidents] }
    }),

  updateGraph: (data) => set({ graphData: data }),

  // MERGE stats — partial WS updates won't wipe unrelated fields
  updateStats: (partial) =>
    set((state) => ({
      stats: { ...state.stats, ...partial },
    })),

  updateAlertStatus: (eventId, status) => set(state => ({
    alerts: state.alerts.map(a => a.event_id === eventId ? { ...a, status } : a)
  })),

  selectIncident: (id) => set({ selectedIncident: id }),

  setSimulationRunning: (val) => set({ simulationRunning: val }),

  clearAlerts: () =>
    set({
      alerts: [],
      incidents: [],
      stats: {
        total_events: 0,
        events_per_second: 0,
        total_alerts: 0,
        alerts_by_severity: {},
        false_positive_rate: 0,
        current_file: null,
        analysis_complete: false,
      },
    }),
}))

if (typeof window !== 'undefined') {
  window.useAlertStore = useAlertStore
}

export default useAlertStore
