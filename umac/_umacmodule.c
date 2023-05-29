#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#include "umac.h"

static PyObject *UmacError;

typedef struct {
    PyObject_HEAD
    umac_ctx_t umac_ctx;
} UmacObject;

static void
Umac_dealloc(UmacObject *self) {
    umac_delete(self->umac_ctx);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Umac_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    UmacObject *self;
    self = (UmacObject *) type->tp_alloc(type, 0);
    self->umac_ctx = NULL;
    return (PyObject *) self;
}

static int
Umac_init(UmacObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {"key", NULL};
    const char *key;
    Py_ssize_t key_length;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist,
                                     &key, &key_length)) {
        return -1;
    }
    if (key_length != 16) {
        PyErr_SetString(UmacError, "key length must be 16");
        return -1;
    }
    self->umac_ctx = umac_new(key);
    return 0;
}

// 定义实例属性
static PyMemberDef Umac_members[] = {
        {NULL}  /* Sentinel */
};

static PyObject *
Umac_mac(UmacObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {"message", "nonce", NULL};
    const char *message;
    Py_ssize_t message_length;
    const char *nonce;
    Py_ssize_t nonce_length;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#y#", kwlist,
                                     &message, &message_length,
                                     &nonce, &nonce_length)) {
        return NULL;
    }
    if (nonce_length != 8) {
        PyErr_SetString(UmacError, "nonce length must be 8");
        return NULL;
    }
    char tag[8];
    umac_update(self->umac_ctx, message, message_length);
    umac_final(self->umac_ctx, tag, nonce);
    return Py_BuildValue("y#", tag, (Py_ssize_t) 8);
}

static PyMethodDef Umac_methods[] = {
        {"mac", (PyCFunction) Umac_mac, METH_VARARGS | METH_KEYWORDS,
                "calculate mac",
        },
        {NULL}  /* Sentinel */
};

static PyTypeObject UmacType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "_umac.Umac",
        .tp_doc = PyDoc_STR("Umac objects"),
        .tp_basicsize = sizeof(UmacObject),
        .tp_itemsize = 0,
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = Umac_new,
        .tp_init = (initproc) Umac_init,
        .tp_dealloc = (destructor) Umac_dealloc,
        .tp_members = Umac_members,
        .tp_methods = Umac_methods,
};

typedef struct {
    PyObject_HEAD
    umac_ctx_t umac_ctx;
} Umac128Object;

static void
Umac128_dealloc(Umac128Object *self) {
    umac128_delete(self->umac_ctx);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Umac128_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    Umac128Object *self;
    self = (Umac128Object *) type->tp_alloc(type, 0);
    self->umac_ctx = NULL;
    return (PyObject *) self;
}

static int
Umac128_init(Umac128Object *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {"key", NULL};
    const char *key;
    Py_ssize_t key_length;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist,
                                     &key, &key_length)) {
        return -1;
    }
    if (key_length != 16) {
        PyErr_SetString(UmacError, "key length must be 16");
        return -1;
    }
    self->umac_ctx = umac128_new(key);
    return 0;
}

// 定义实例属性
static PyMemberDef Umac128_members[] = {
        {NULL}  /* Sentinel */
};

static PyObject *
Umac128_mac(Umac128Object *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {"message", "nonce", NULL};
    const char *message;
    Py_ssize_t message_length;
    const char *nonce;
    Py_ssize_t nonce_length;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#y#", kwlist,
                                     &message, &message_length,
                                     &nonce, &nonce_length)) {
        return NULL;
    }
    if (nonce_length != 8) {
        PyErr_SetString(UmacError, "nonce length must be 8");
        return NULL;
    }
    char tag[16];
    umac128_update(self->umac_ctx, message, message_length);
    umac128_final(self->umac_ctx, tag, nonce);
    return Py_BuildValue("y#", tag, (Py_ssize_t) 16);
}

static PyMethodDef Umac128_methods[] = {
        {"mac", (PyCFunction) Umac128_mac, METH_VARARGS | METH_KEYWORDS,
                "calculate mac",
        },
        {NULL}  /* Sentinel */
};

static PyTypeObject Umac128Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "_umac.Umac128",
        .tp_doc = PyDoc_STR("Umac128 objects"),
        .tp_basicsize = sizeof(Umac128Object),
        .tp_itemsize = 0,
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = Umac128_new,
        .tp_init = (initproc) Umac128_init,
        .tp_dealloc = (destructor) Umac128_dealloc,
        .tp_members = Umac128_members,
        .tp_methods = Umac128_methods,
};

static PyModuleDef _umacmodule = {
        PyModuleDef_HEAD_INIT,
        .m_name = "_umac",
        .m_doc = "umac c implement.",
        .m_size = -1,
};

PyMODINIT_FUNC
PyInit__umac(void) {
    PyObject *m;
    if (PyType_Ready(&UmacType) < 0) {
        return NULL;
    }
    if (PyType_Ready(&Umac128Type) < 0) {
        return NULL;
    }

    m = PyModule_Create(&_umacmodule);
    if (m == NULL) {
        return NULL;
    }

    Py_INCREF(&UmacType);
    if (PyModule_AddObject(m, "Umac", (PyObject *) &UmacType) < 0) {
        Py_DECREF(&UmacType);
        Py_DECREF(m);
        return NULL;
    }

    Py_INCREF(&Umac128Type);
    if (PyModule_AddObject(m, "Umac128", (PyObject *) &Umac128Type) < 0) {
        Py_DECREF(&Umac128Type);
        Py_DECREF(&UmacType);
        Py_DECREF(m);
        return NULL;
    }

    UmacError = PyErr_NewException("umac.UmacError", NULL, NULL);
    Py_XINCREF(UmacError);
    if (PyModule_AddObject(m, "UmacError", UmacError) < 0) {
        Py_DECREF(&Umac128Type);
        Py_DECREF(&UmacType);
        Py_XDECREF(UmacError);
        Py_CLEAR(UmacError);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}