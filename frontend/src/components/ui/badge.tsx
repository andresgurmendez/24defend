import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
  {
    variants: {
      variant: {
        neutral: 'bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]',
        accent: 'bg-[var(--color-accent-soft)] text-[var(--color-accent)]',
        danger: 'bg-[var(--color-danger-soft)] text-[var(--color-danger)]',
        warning: 'bg-[var(--color-warning-soft)] text-[var(--color-warning)]',
        success: 'bg-[var(--color-success-soft)] text-[var(--color-success)]',
      },
    },
    defaultVariants: {
      variant: 'neutral',
    },
  },
)

interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
