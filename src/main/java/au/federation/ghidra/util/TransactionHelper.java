package au.federation.ghidra.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import javax.swing.SwingUtilities;
import ghidra.util.SystemUtilities;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicReference;

public class TransactionHelper {
    
    @FunctionalInterface
    public interface GhidraSupplier<T> {
        T get() throws Exception;
    }

    public static <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation)
            throws TransactionException {

        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();

        Runnable task = () -> {
            boolean successFlag = false;
            Object newTx = null;
            Method commitMethod = null;
            Method closeMethod = null;
            boolean usedNewApi = false;

            Integer oldTxId = null;
            Method endTransactionMethod = null;

            try {
                // Try new API: program.openTransaction(String) -> Transaction with commit()/close()
                try {
                    Method openTx = program.getClass().getMethod("openTransaction", String.class);
                    newTx = openTx.invoke(program, transactionName);
                    commitMethod = newTx.getClass().getMethod("commit");
                    closeMethod = newTx.getClass().getMethod("close");
                    usedNewApi = true;
                } catch (NoSuchMethodException nsme) {
                    // Fallback to legacy API
                    try {
                        Method startTransactionMethod = program.getClass().getMethod("startTransaction", String.class);
                        Object idObj = startTransactionMethod.invoke(program, transactionName);
                        oldTxId = (idObj instanceof Integer) ? (Integer) idObj : null;
                        if (oldTxId == null || oldTxId < 0) {
                            throw new TransactionException("Failed to start transaction: " + transactionName);
                        }
                        // Resolve endTransaction reflectively to avoid NoSuchMethodError at runtime
                        endTransactionMethod = program.getClass().getMethod("endTransaction", int.class, boolean.class);
                    } catch (NoSuchMethodException nsme2) {
                        throw new TransactionException("No supported transaction API found on Program (openTransaction/startTransaction missing)", nsme2);
                    }
                }

                // Execute the user operation
                T opResult = operation.get();
                result.set(opResult);

                // Determine commit/rollback
                if (opResult instanceof Boolean) {
                    successFlag = Boolean.TRUE.equals(opResult);
                } else {
                    successFlag = true; // commit by default when no error
                }

                // Commit for new API immediately (close in finally)
                if (usedNewApi && successFlag && commitMethod != null && newTx != null) {
                    commitMethod.invoke(newTx);
                }
            } catch (Exception e) {
                exception.set(e instanceof TransactionException ? e : new TransactionException("Transaction failed: " + transactionName, e));
                Msg.error(TransactionHelper.class, "Transaction failed: " + transactionName, e);
            } finally {
                try {
                    if (usedNewApi) {
                        // Close new API transaction (rolls back if not committed)
                        if (newTx != null && closeMethod != null) {
                            try {
                                closeMethod.invoke(newTx);
                            } catch (Exception ce) {
                                Msg.error(TransactionHelper.class, "Failed to close transaction (new API)", ce);
                            }
                        }
                    } else if (oldTxId != null) {
                        // Legacy API endTransaction
                        try {
                            boolean commit = (exception.get() == null) && successFlag;
                            if (endTransactionMethod != null) {
                                endTransactionMethod.invoke(program, oldTxId, commit);
                            }
                        } catch (Exception ie) {
                            Msg.error(TransactionHelper.class, "Failed to end transaction (legacy API)", ie);
                        }
                    }
                } catch (Exception closingEx) {
                    Msg.error(TransactionHelper.class, "Unexpected error finalizing transaction", closingEx);
                }
            }
        };

        try {
            // Prefer Ghidra's SystemUtilities to marshal to EDT, detect EDT with SwingUtilities
            if (SwingUtilities.isEventDispatchThread()) {
                task.run();
            } else {
                SystemUtilities.runSwingNow(task);
            }
        } catch (Exception e) {
            throw new TransactionException("Swing thread execution failed", e);
        }

        if (exception.get() != null) {
            throw new TransactionException("Operation failed", exception.get());
        }
        return result.get();
    }

    public static class TransactionException extends Exception {
        public TransactionException(String message) { super(message); }
        public TransactionException(String message, Throwable cause) { super(message, cause); }
    }
}
