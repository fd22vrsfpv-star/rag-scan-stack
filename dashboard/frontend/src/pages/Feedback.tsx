import { useState } from 'react'
import { useFeedbackList, useExportFeedback, useCreateFeedback } from '@/api/feedback'
import { Star, Download, Check } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

const TASK_TYPES = [
  { value: 'scan_analysis', label: 'Scan Analysis' },
  { value: 'exploit_recommendation', label: 'Exploit Recommendation' },
  { value: 'agent_decision', label: 'Agent Decision' },
]

export default function Feedback() {
  const { data: feedbackData, isLoading } = useFeedbackList()
  const exportFeedback = useExportFeedback()
  const createFeedback = useCreateFeedback()
  const [taskType, setTaskType] = useState('scan_analysis')
  const [rating, setRating] = useState(0)
  const [comment, setComment] = useState('')
  const [submitted, setSubmitted] = useState(false)

  const handleSubmit = () => {
    if (rating === 0) return
    createFeedback.mutate({
      rating,
      comment: comment || undefined,
      context: { type: 'manual_feedback', task_type: taskType },
    }, {
      onSuccess: () => {
        setSubmitted(true)
        setTimeout(() => {
          setSubmitted(false)
          setRating(0)
          setComment('')
          setTaskType('scan_analysis')
        }, 3000)
      },
    })
  }

  const items = Array.isArray(feedbackData) ? feedbackData : []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Feedback</h2>
        <button
          onClick={() => exportFeedback.refetch()}
          className="flex items-center gap-2 px-3 py-1.5 bg-secondary text-secondary-foreground rounded-md text-sm"
        >
          <Download className="h-4 w-4" /> Export Training Data
        </button>
      </div>

      {/* Submit Training Feedback */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold">Submit Training Feedback</h3>
        {submitted ? (
          <div className="flex items-center gap-1.5 text-green-400 text-sm">
            <Check className="h-4 w-4" /> Submitted!
          </div>
        ) : (
          <>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Task Type</label>
              <select
                value={taskType}
                onChange={e => setTaskType(e.target.value)}
                className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                {TASK_TYPES.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Rating</label>
              <div className="flex items-center gap-0.5">
                {[1, 2, 3, 4, 5].map(n => (
                  <button key={n} onClick={() => setRating(n)} className="p-0.5">
                    <Star
                      className={cn('h-5 w-5 cursor-pointer', n <= rating ? 'fill-yellow-400 text-yellow-400' : 'text-muted-foreground')}
                    />
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Comment</label>
              <textarea
                placeholder="Optional comment..."
                value={comment}
                onChange={e => setComment(e.target.value)}
                className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-none h-16"
              />
            </div>
            <button
              onClick={handleSubmit}
              disabled={rating === 0 || createFeedback.isPending}
              className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm disabled:opacity-50"
            >
              {createFeedback.isPending ? 'Submitting...' : 'Submit'}
            </button>
            {createFeedback.isError && (
              <p className="text-xs text-red-400">Failed to submit feedback</p>
            )}
          </>
        )}
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

      <div className="space-y-2">
        {items.map(fb => (
          <div key={fb.id} className="bg-card border border-border rounded-lg p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1">
                {[1, 2, 3, 4, 5].map(n => (
                  <Star
                    key={n}
                    className={cn('h-3.5 w-3.5', n <= fb.rating ? 'fill-yellow-400 text-yellow-400' : 'text-muted-foreground')}
                  />
                ))}
              </div>
              <span className="text-xs text-muted-foreground">{fb.created_at ? formatDate(fb.created_at) : ''}</span>
            </div>
            {fb.comment && <p className="text-sm mt-1.5">{fb.comment}</p>}
            {fb.session_id && <p className="text-xs text-muted-foreground mt-1 font-mono">Session: {fb.session_id}</p>}
          </div>
        ))}
        {items.length === 0 && !isLoading && (
          <p className="text-sm text-muted-foreground text-center py-8">No feedback entries yet</p>
        )}
      </div>
    </div>
  )
}
