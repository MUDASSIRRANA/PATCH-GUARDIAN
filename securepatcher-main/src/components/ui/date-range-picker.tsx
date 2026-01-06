import * as React from "react";
import { format } from "date-fns";
import { Calendar as CalendarIcon } from "lucide-react";
import { DateRange } from "react-day-picker";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

interface DatePickerWithRangeProps extends React.HTMLAttributes<HTMLDivElement> {
  date?: DateRange;
  onDateChange?: (date: DateRange | undefined) => void;
}

export function DatePickerWithRange({
  className,
  date,
  onDateChange,
}: DatePickerWithRangeProps) {
  const [dateRange, setDateRange] = React.useState<DateRange | undefined>(date);

  const handleDateChange = (newDate: DateRange | undefined) => {
    setDateRange(newDate);
    onDateChange?.(newDate);
  };

  return (
    <div className={cn("grid gap-2", className)}>
      <Popover>
        <PopoverTrigger asChild>
          <Button
            className={cn(
              "w-full justify-center text-center font-normal bg-cyan-500 hover:bg-cyan-600 text-white",
              !dateRange && "opacity-80"
            )}
          >
            <CalendarIcon className="mr-2 h-4 w-4 text-white" />
            {dateRange?.from ? (
              dateRange.to ? (
                <>
                  {format(dateRange.from, "LLL dd, y")} -{" "}
                  {format(dateRange.to, "LLL dd, y")}
                </>
              ) : (
                format(dateRange.from, "LLL dd, y")
              )
            ) : (
              <span>Pick a date range</span>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-auto p-0 bg-black border-gray-800" align="start">
          <Calendar
            initialFocus
            mode="range"
            defaultMonth={dateRange?.from}
            selected={dateRange}
            onSelect={handleDateChange}
            numberOfMonths={2}
            className="bg-black text-white"
          />
        </PopoverContent>
      </Popover>
    </div>
  );
}

function getAuthToken() {
  const sessionStr = localStorage.getItem('session');
  if (!sessionStr) return null;
  try {
    const session = JSON.parse(sessionStr);
    // Check expiry
    if (session.expiresAt && new Date(session.expiresAt) < new Date()) {
      localStorage.removeItem('session');
      return null;
    }
    return session?.token || null;
  } catch {
    return null;
  }
}

const session = JSON.parse(localStorage.getItem('session') || '{}');
localStorage.setItem('session', JSON.stringify({
  ...session,
  // any new fields you want to update
}));

localStorage.removeItem('token');
localStorage.removeItem('user'); 