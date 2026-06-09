import { useEffect, useRef, useState, useCallback } from 'react'

export function useBlipSocket(onEvent) {
  const [connected, setConnected] = useState(false)
  const wsRef     = useRef(null)
  const retryRef  = useRef(null)
  const delay     = useRef(1000)

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws    = new WebSocket(`${proto}://${window.location.host}/ws`)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      delay.current = 1000
    }

    ws.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data)
        onEvent(event)
      } catch (_) {}
    }

    ws.onclose = () => {
      setConnected(false)
      retryRef.current = setTimeout(() => {
        delay.current = Math.min(delay.current * 2, 16000)
        connect()
      }, delay.current)
    }

    ws.onerror = () => ws.close()
  }, [onEvent])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(retryRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  // keep-alive ping every 20s
  useEffect(() => {
    const id = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping')
      }
    }, 20000)
    return () => clearInterval(id)
  }, [])

  return connected
}
